const SETTINGS_KEY = "threatspectra_settings_v2";
const HISTORY_KEY = "threatspectra_history_v2";
const MAX_HISTORY_ITEMS = 15;

const DEFAULT_SETTINGS = {
  popupEnabled: true,
  apiBaseUrl: "http://127.0.0.1:5000"
};

const lastScanByTab = new Map();

function normalizeApiBaseUrl(rawUrl) {
  const fallback = DEFAULT_SETTINGS.apiBaseUrl;
  if (!rawUrl || typeof rawUrl !== "string") {
    return fallback;
  }

  const cleaned = rawUrl.trim().replace(/\/+$/, "");
  return cleaned || fallback;
}

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get([SETTINGS_KEY], (stored) => {
      const fromStorage = stored && stored[SETTINGS_KEY] ? stored[SETTINGS_KEY] : {};
      const merged = {
        popupEnabled: typeof fromStorage.popupEnabled === "boolean"
          ? fromStorage.popupEnabled
          : DEFAULT_SETTINGS.popupEnabled,
        apiBaseUrl: normalizeApiBaseUrl(fromStorage.apiBaseUrl || DEFAULT_SETTINGS.apiBaseUrl)
      };
      resolve(merged);
    });
  });
}

function saveSettings(nextPartial) {
  return new Promise(async (resolve) => {
    const current = await getSettings();
    const next = {
      ...current,
      ...nextPartial,
      apiBaseUrl: normalizeApiBaseUrl((nextPartial && nextPartial.apiBaseUrl) || current.apiBaseUrl)
    };

    chrome.storage.local.set({ [SETTINGS_KEY]: next }, () => {
      resolve(next);
    });
  });
}

function getHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.get([HISTORY_KEY], (stored) => {
      const list = Array.isArray(stored && stored[HISTORY_KEY]) ? stored[HISTORY_KEY] : [];
      resolve(list);
    });
  });
}

function saveHistory(historyList) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [HISTORY_KEY]: historyList }, () => {
      resolve(historyList);
    });
  });
}

async function addHistoryItem(item) {
  const list = await getHistory();
  const next = [item, ...list].slice(0, MAX_HISTORY_ITEMS);
  await saveHistory(next);
  return next;
}

async function deleteHistoryItem(itemId) {
  const list = await getHistory();
  const next = list.filter((item) => item.id !== itemId);
  await saveHistory(next);
  return next;
}

async function clearHistory() {
  await saveHistory([]);
  return [];
}

function toStatus(result) {
  const normalized = String(result || "").toLowerCase();
  if (normalized === "safe") {
    return "safe";
  }
  if (normalized === "phishing" || normalized === "unsafe") {
    return "unsafe";
  }
  return "unknown";
}

function toLabel(status) {
  if (status === "safe") {
    return "Safe";
  }
  if (status === "unsafe") {
    return "Unsafe";
  }
  return "Unknown";
}

function buildPayloadFromPrediction(url, prediction) {
  const status = toStatus(prediction.result);
  return {
    status,
    label: toLabel(status),
    confidence: Number(prediction.confidence || 0),
    riskLevel: prediction.risk_level || "Unknown",
    reason: Array.isArray(prediction.reasons) && prediction.reasons.length
      ? prediction.reasons[0]
      : "No details provided.",
    scannedUrl: url,
    scannedAt: Date.now()
  };
}

async function requestUrlPrediction(apiBaseUrl, pageUrl) {
  const response = await fetch(`${normalizeApiBaseUrl(apiBaseUrl)}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: pageUrl })
  });

  if (!response.ok) {
    throw new Error(`Prediction request failed (${response.status})`);
  }

  return response.json();
}

function isScannableUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function sendAlertToTab(tabId, payload) {
  if (!Number.isInteger(tabId) || tabId <= 0) {
    return;
  }

  chrome.tabs.sendMessage(
    tabId,
    {
      type: "THREATSPECTRA_SHOW_ALERT",
      payload
    },
    () => {
      // This happens on restricted/internal pages or before content script is ready.
      if (chrome.runtime.lastError) {
        return;
      }
    }
  );
}

async function scanUrlAndMaybeNotify(tabId, url, options = {}) {
  const { force = false, source = "auto" } = options;

  if (!isScannableUrl(url)) {
    return { ok: false, reason: "unsupported_url" };
  }

  const key = `${tabId}:${url}`;
  if (!force && lastScanByTab.get(tabId) === key) {
    return { ok: true, skipped: true, reason: "already_scanned" };
  }

  const settings = await getSettings();

  try {
    const prediction = await requestUrlPrediction(settings.apiBaseUrl, url);
    const payload = buildPayloadFromPrediction(url, prediction);

    await addHistoryItem({
      id: `${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
      type: "url",
      target: url,
      status: payload.status,
      label: payload.label,
      confidence: payload.confidence,
      riskLevel: payload.riskLevel,
      createdAt: payload.scannedAt,
      source
    });

    if (settings.popupEnabled) {
      sendAlertToTab(tabId, payload);
    }

    lastScanByTab.set(tabId, key);
    return { ok: true, payload };
  } catch (error) {
    return {
      ok: false,
      reason: "prediction_error",
      error: error && error.message ? error.message : "Unknown error"
    };
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await getSettings();
  await saveSettings(settings);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    // Reset the tab cache on each navigation/refresh so alerts can reappear.
    lastScanByTab.delete(tabId);
    return;
  }

  if (changeInfo.url && tab && tab.url) {
    scanUrlAndMaybeNotify(tabId, tab.url, { source: "auto" });
    return;
  }

  if (changeInfo.status !== "complete") {
    return;
  }

  if (!tab || !tab.url) {
    return;
  }

  scanUrlAndMaybeNotify(tabId, tab.url, { source: "auto" });
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (!tab || !tab.url) {
      return;
    }

    scanUrlAndMaybeNotify(tab.id, tab.url, { source: "auto" });
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") {
    return false;
  }

  if (message.type === "THREATSPECTRA_SETTINGS_GET") {
    getSettings().then((settings) => {
      sendResponse({ ok: true, settings });
    });
    return true;
  }

  if (message.type === "THREATSPECTRA_POPUP_TOGGLE_SET") {
    saveSettings({ popupEnabled: Boolean(message.popupEnabled) }).then((settings) => {
      sendResponse({ ok: true, settings });
    });
    return true;
  }

  if (message.type === "THREATSPECTRA_URL_SCAN") {
    const tabId = Number(message.tabId || (sender.tab && sender.tab.id));
    const tabUrl = String(message.url || "").trim();

    scanUrlAndMaybeNotify(tabId, tabUrl, { force: true, source: "manual" }).then((result) => {
      sendResponse(result);
    });

    return true;
  }

  if (message.type === "THREATSPECTRA_HISTORY_GET") {
    getHistory().then((history) => {
      sendResponse({ ok: true, history });
    });
    return true;
  }

  if (message.type === "THREATSPECTRA_HISTORY_DELETE") {
    deleteHistoryItem(String(message.id || "")).then((history) => {
      sendResponse({ ok: true, history });
    });
    return true;
  }

  if (message.type === "THREATSPECTRA_HISTORY_CLEAR") {
    clearHistory().then((history) => {
      sendResponse({ ok: true, history });
    });
    return true;
  }

  return false;
});