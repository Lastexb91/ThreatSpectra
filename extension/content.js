const ALERT_ID = "threatspectra-site-alert";

function confidencePercent(confidence) {
  if (!Number.isFinite(confidence)) {
    return "N/A";
  }

  return `${Math.round(confidence * 100)}%`;
}

function getTheme(status) {
  if (status === "safe") {
    return {
      tone: "SAFE",
      border: "#10b981",
      glow: "rgba(16, 185, 129, 0.35)",
      bg: "linear-gradient(140deg, rgba(16, 185, 129, 0.96), rgba(5, 150, 105, 0.96))"
    };
  }

  if (status === "unsafe") {
    return {
      tone: "UNSAFE",
      border: "#ef4444",
      glow: "rgba(239, 68, 68, 0.38)",
      bg: "linear-gradient(140deg, rgba(239, 68, 68, 0.96), rgba(190, 24, 93, 0.95))"
    };
  }

  return {
    tone: "UNKNOWN",
    border: "#f59e0b",
    glow: "rgba(245, 158, 11, 0.38)",
    bg: "linear-gradient(140deg, rgba(245, 158, 11, 0.96), rgba(217, 119, 6, 0.95))"
  };
}

function removeExistingAlert() {
  const oldAlert = document.getElementById(ALERT_ID);
  if (oldAlert) {
    oldAlert.remove();
  }
}

function buildAlertCard(payload) {
  const theme = getTheme(payload.status);
  const card = document.createElement("div");
  card.id = ALERT_ID;
  card.style.position = "fixed";
  card.style.top = "18px";
  card.style.right = "18px";
  card.style.zIndex = "2147483647";
  card.style.minWidth = "300px";
  card.style.maxWidth = "360px";
  card.style.padding = "14px 14px 12px";
  card.style.borderRadius = "16px";
  card.style.border = `1px solid ${theme.border}`;
  card.style.background = theme.bg;
  card.style.backdropFilter = "blur(6px)";
  card.style.boxShadow = `0 14px 30px ${theme.glow}`;
  card.style.color = "#f8fafc";
  card.style.fontFamily = '"Space Grotesk", "Segoe UI", sans-serif';
  card.style.letterSpacing = "0.2px";
  card.style.transform = "translateY(-10px) scale(0.98)";
  card.style.opacity = "0";
  card.style.transition = "all 220ms ease";

  card.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px;">
      <strong style="font-size:15px;line-height:1.2;">ThreatSpectra Scan</strong>
      <div style="display:flex;align-items:center;gap:6px;">
        <span style="font-size:11px;font-weight:700;letter-spacing:0.8px;padding:4px 8px;border-radius:999px;background:rgba(15,23,42,0.25);">${theme.tone}</span>
        <button id="threatspectra-alert-close" type="button" aria-label="Close alert" style="width:24px;height:24px;border:none;border-radius:8px;background:rgba(15,23,42,0.28);color:#f8fafc;font-size:14px;line-height:1;cursor:pointer;">x</button>
      </div>
    </div>
    <div style="font-size:13px;line-height:1.4;margin-bottom:8px;">
      This site is <strong>${payload.label}</strong>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;">
      <div style="background:rgba(2,6,23,0.22);padding:8px;border-radius:10px;">
        <div style="opacity:0.82;">Confidence</div>
        <div style="font-weight:700;">${confidencePercent(payload.confidence)}</div>
      </div>
      <div style="background:rgba(2,6,23,0.22);padding:8px;border-radius:10px;">
        <div style="opacity:0.82;">Risk</div>
        <div style="font-weight:700;">${payload.riskLevel || "Unknown"}</div>
      </div>
    </div>
  `;

  const closeButton = card.querySelector("#threatspectra-alert-close");
  if (closeButton) {
    closeButton.addEventListener("click", () => {
      if (card.isConnected) {
        card.remove();
      }
    });
  }

  return card;
}

function showAlert(payload) {
  removeExistingAlert();

  const card = buildAlertCard(payload);
  document.documentElement.appendChild(card);

  requestAnimationFrame(() => {
    card.style.opacity = "1";
    card.style.transform = "translateY(0) scale(1)";
  });

  window.setTimeout(() => {
    card.style.opacity = "0";
    card.style.transform = "translateY(-8px) scale(0.98)";
    window.setTimeout(() => {
      if (card.isConnected) {
        card.remove();
      }
    }, 260);
  }, 4500);
}

chrome.runtime.onMessage.addListener((message) => {
  if (!message || message.type !== "THREATSPECTRA_SHOW_ALERT") {
    return;
  }

  showAlert(message.payload || {});
});