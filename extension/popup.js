const API_BASE_URL = "https://threat-spectra--krishyada9865.replit.app";
const MAX_HISTORY_ITEMS = 15;

const statusText = document.getElementById("status-text");
const popupToggle = document.getElementById("popup-toggle");
const urlInput = document.getElementById("url-input");
const qrFileInput = document.getElementById("qr-file");
const emailInput = document.getElementById("email-input");
const smsInput = document.getElementById("sms-input");
const scanUrlButton = document.getElementById("scan-url");
const scanQrButton = document.getElementById("scan-qr");
const scanEmailButton = document.getElementById("scan-email");
const scanSmsButton = document.getElementById("scan-sms");
const clearHistoryButton = document.getElementById("clear-history");
const historyList = document.getElementById("history-list");
const urlOutput = document.getElementById("url-output");
const qrOutput = document.getElementById("qr-output");
const emailOutput = document.getElementById("email-output");
const smsOutput = document.getElementById("sms-output");
const tabButtons = Array.from(document.querySelectorAll(".tab-btn"));
const panels = {
  url: document.getElementById("panel-url"),
  qr: document.getElementById("panel-qr"),
  email: document.getElementById("panel-email"),
  sms: document.getElementById("panel-sms"),
  history: document.getElementById("panel-history")
};

function setStatus(message, kind = "idle") {
  statusText.textContent = message;
  statusText.className = `status ${kind}`;
}

function setOutput(targetEl, message, kind = "idle") {
  if (!targetEl) {
    return;
  }

  targetEl.textContent = message;
  targetEl.className = `result-box ${kind}`;
}

function setActiveTab(tabName) {
  tabButtons.forEach((button) => {
    const isActive = button.getAttribute("data-tab") === tabName;
    button.classList.toggle("active", isActive);
  });

  Object.keys(panels).forEach((name) => {
    const panel = panels[name];
    if (!panel) {
      return;
    }
    panel.classList.toggle("active", name === tabName);
  });
}

function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      resolve(response);
    });
  });
}

function statusFromResultText(resultText) {
  const normalized = String(resultText || "").toLowerCase();
  if (normalized === "safe") {
    return "safe";
  }
  if (normalized === "phishing" || normalized === "unsafe") {
    return "unsafe";
  }
  return "unknown";
}

function prettyTime(unixTimeMs) {
  const date = new Date(unixTimeMs || Date.now());
  return date.toLocaleString();
}

function renderHistoryItem(item) {
  const wrapper = document.createElement("div");
  wrapper.className = "history-item";

  const badgeClass = item.status || "unknown";
  const target = item.target || "Unknown target";

  wrapper.innerHTML = `
    <div class="history-row">
      <span class="badge ${badgeClass}">${(item.label || "Unknown").toUpperCase()}</span>
      <button class="delete-btn" data-id="${item.id}">Delete</button>
    </div>
    <div class="history-url">${target}</div>
    <div class="history-row">
      <small>${item.type ? item.type.toUpperCase() : "SCAN"}</small>
      <small>${prettyTime(item.createdAt)}</small>
    </div>
  `;

  return wrapper;
}

async function refreshHistory() {
  const response = await sendMessage({ type: "THREATSPECTRA_HISTORY_GET" });
  historyList.innerHTML = "";

  if (!response || !response.ok) {
    const empty = document.createElement("div");
    empty.className = "history-item";
    empty.textContent = "Could not load history.";
    historyList.appendChild(empty);
    return;
  }

  const list = Array.isArray(response.history) ? response.history : [];
  if (!list.length) {
    const empty = document.createElement("div");
    empty.className = "history-item";
    empty.textContent = "No history yet.";
    historyList.appendChild(empty);
    return;
  }

  list.forEach((item) => {
    historyList.appendChild(renderHistoryItem(item));
  });
}

async function loadToggle() {
  const response = await sendMessage({ type: "THREATSPECTRA_SETTINGS_GET" });
  if (!response || !response.ok || !response.settings) {
    popupToggle.checked = true;
    return;
  }

  popupToggle.checked = Boolean(response.settings.popupEnabled);
}

async function saveToggle() {
  const response = await sendMessage({
    type: "THREATSPECTRA_POPUP_TOGGLE_SET",
    popupEnabled: popupToggle.checked
  });

  if (!response || !response.ok) {
    setStatus("Could not update toggle setting.", "unsafe");
    return;
  }

  setStatus(
    popupToggle.checked
      ? "Automatic popup alert is ON."
      : "Automatic popup alert is OFF.",
    "safe"
  );
}

function normalizeUrl(raw) {
  const text = String(raw || "").trim();
  if (!text) {
    return "";
  }

  if (!/^https?:\/\//i.test(text)) {
    return `https://${text}`;
  }

  return text;
}

function addManualHistoryEntry(entry) {
  sendMessage({ type: "THREATSPECTRA_HISTORY_GET" }).then((resp) => {
    if (!resp || !resp.ok) {
      refreshHistory();
      return;
    }

    const history = Array.isArray(resp.history) ? resp.history : [];
    const next = [{
      id: `${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
      ...entry,
      createdAt: Date.now(),
      source: "manual"
    }, ...history].slice(0, MAX_HISTORY_ITEMS);

    chrome.storage.local.set({ threatspectra_history_v2: next }, () => {
      refreshHistory();
    });
  });
}

async function scanUrl() {
  const url = normalizeUrl(urlInput.value);
  if (!url) {
    setStatus("Please enter a URL.", "unknown");
    setOutput(urlOutput, "Please enter a valid URL.", "unknown");
    return;
  }

  setStatus("Scanning URL...", "idle");

  const result = await sendMessage({
    type: "THREATSPECTRA_URL_SCAN",
    tabId: -1,
    url
  });

  if (!result || !result.ok) {
    setStatus(`URL scan failed: ${(result && result.error) || "Unknown error"}`, "unsafe");
    setOutput(urlOutput, `Scan failed: ${(result && result.error) || "Unknown error"}`, "unsafe");
    return;
  }

  const payload = result.payload || {};
  setStatus(`URL Result: ${payload.label || "Unknown"}`, payload.status || "unknown");
  setOutput(
    urlOutput,
    `Result: ${payload.label || "Unknown"} | Confidence: ${Number.isFinite(payload.confidence) ? Math.round(payload.confidence * 100) + "%" : "N/A"} | Risk: ${payload.riskLevel || "Unknown"}`,
    payload.status || "unknown"
  );
  refreshHistory();
}

async function scanEmail() {
  const emailText = String(emailInput.value || "").trim();
  if (!emailText) {
    setStatus("Please paste email text.", "unknown");
    setOutput(emailOutput, "Please paste email text first.", "unknown");
    return;
  }

  setStatus("Scanning email...", "idle");

  try {
    const response = await fetch(`${API_BASE_URL}/predict_email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: emailText })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Email scan failed");
    }

    const status = statusFromResultText(data.result || data.prediction);
    setStatus(`Email Result: ${data.result || data.prediction || "Unknown"}`, status);
    setOutput(
      emailOutput,
      `Result: ${data.result || data.prediction || "Unknown"} | Confidence: ${Number.isFinite(Number(data.confidence)) ? Math.round(Number(data.confidence) * 100) + "%" : "N/A"}`,
      status
    );

    addManualHistoryEntry({
      type: "email",
      target: emailText.slice(0, 60) + (emailText.length > 60 ? "..." : ""),
      status,
      label: status === "safe" ? "Safe" : status === "unsafe" ? "Unsafe" : "Unknown",
      confidence: Number(data.confidence || 0),
      riskLevel: data.risk_level || "Unknown"
    });
  } catch (error) {
    setStatus(`Email scan failed: ${error.message}`, "unsafe");
    setOutput(emailOutput, `Scan failed: ${error.message}`, "unsafe");
  }
}

async function scanSms() {
  const smsText = String(smsInput.value || "").trim();
  if (!smsText) {
    setStatus("Please paste SMS text.", "unknown");
    setOutput(smsOutput, "Please paste SMS text first.", "unknown");
    return;
  }

  setStatus("Scanning SMS...", "idle");

  try {
    const response = await fetch(`${API_BASE_URL}/predict/sms`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: smsText })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "SMS scan failed");
    }

    const status = statusFromResultText(data.result || data.prediction);
    setStatus(`SMS Result: ${data.result || data.prediction || "Unknown"}`, status);
    setOutput(
      smsOutput,
      `Result: ${data.result || data.prediction || "Unknown"} | Confidence: ${Number.isFinite(Number(data.confidence)) ? Math.round(Number(data.confidence) * 100) + "%" : "N/A"}`,
      status
    );

    addManualHistoryEntry({
      type: "sms",
      target: smsText.slice(0, 60) + (smsText.length > 60 ? "..." : ""),
      status,
      label: status === "safe" ? "Safe" : status === "unsafe" ? "Unsafe" : "Unknown",
      confidence: Number(data.confidence || 0),
      riskLevel: data.risk_level || "Unknown"
    });
  } catch (error) {
    setStatus(`SMS scan failed: ${error.message}`, "unsafe");
    setOutput(smsOutput, `Scan failed: ${error.message}`, "unsafe");
  }
}

async function scanQr() {
  const file = qrFileInput.files && qrFileInput.files[0];
  if (!file) {
    setStatus("Please choose a QR image.", "unknown");
    setOutput(qrOutput, "Please choose a QR image first.", "unknown");
    return;
  }

  setStatus("Scanning QR image...", "idle");

  try {
    const formData = new FormData();
    formData.append("qr_image", file);

    const response = await fetch(`${API_BASE_URL}/predict-qr`, {
      method: "POST",
      body: formData
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "QR scan failed");
    }

    const status = statusFromResultText(data.result);
    setStatus(`QR Result: ${data.result || "Unknown"}`, status);
    setOutput(
      qrOutput,
      `Result: ${data.result || "Unknown"} | URL: ${data.url || "Not available"} | Confidence: ${Number.isFinite(Number(data.confidence)) ? Math.round(Number(data.confidence) * 100) + "%" : "N/A"}`,
      status
    );

    addManualHistoryEntry({
      type: "qr",
      target: data.url || file.name,
      status,
      label: status === "safe" ? "Safe" : status === "unsafe" ? "Unsafe" : "Unknown",
      confidence: Number(data.confidence || 0),
      riskLevel: data.risk_level || "Unknown"
    });
  } catch (error) {
    setStatus(`QR scan failed: ${error.message}`, "unsafe");
    setOutput(qrOutput, `Scan failed: ${error.message}`, "unsafe");
  }
}

historyList.addEventListener("click", async (event) => {
  const button = event.target.closest(".delete-btn");
  if (!button) {
    return;
  }

  const id = button.getAttribute("data-id");
  if (!id) {
    return;
  }

  await sendMessage({ type: "THREATSPECTRA_HISTORY_DELETE", id });
  refreshHistory();
});

clearHistoryButton.addEventListener("click", async () => {
  await sendMessage({ type: "THREATSPECTRA_HISTORY_CLEAR" });
  setStatus("History cleared.", "idle");
  refreshHistory();
});

popupToggle.addEventListener("change", saveToggle);
scanUrlButton.addEventListener("click", scanUrl);
scanEmailButton.addEventListener("click", scanEmail);
scanSmsButton.addEventListener("click", scanSms);
scanQrButton.addEventListener("click", scanQr);
tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    setActiveTab(button.getAttribute("data-tab"));
  });
});

document.addEventListener("DOMContentLoaded", async () => {
  setActiveTab("url");
  await loadToggle();
  await refreshHistory();
  setOutput(urlOutput, "No URL scan yet.", "idle");
  setOutput(qrOutput, "No QR scan yet.", "idle");
  setOutput(emailOutput, "No email scan yet.", "idle");
  setOutput(smsOutput, "No SMS scan yet.", "idle");
  setStatus("Ready.", "idle");
});