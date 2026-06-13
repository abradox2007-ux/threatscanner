/* ── ThreatScan — app.js ─────────────────────────────────────────────────── */

const API_BASE = "";   // same origin; change to http://localhost:8000 for dev

/* ── Tab switching ─────────────────────────────────────────────────────────── */
const tabs   = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".tab-panel");

tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => { t.classList.remove("active"); t.setAttribute("aria-selected", "false"); });
    panels.forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
    hideResults();
  });
});

/* ── Character counter ─────────────────────────────────────────────────────── */
const textInput  = document.getElementById("textInput");
const charCount  = document.getElementById("charCount");
const MAX_CHARS  = 50000;

textInput.addEventListener("input", () => {
  const len = textInput.value.length;
  charCount.textContent = `${len.toLocaleString()} / ${MAX_CHARS.toLocaleString()}`;
  charCount.style.color = len > MAX_CHARS * 0.9 ? "var(--suspicious)" : "";
});

document.getElementById("clearText").addEventListener("click", () => {
  textInput.value = "";
  charCount.textContent = "0 / 50,000";
  hideResults();
});

/* ── Image upload ──────────────────────────────────────────────────────────── */
const dropZone        = document.getElementById("dropZone");
const imageInput      = document.getElementById("imageInput");
const imagePreviewWrap = document.getElementById("imagePreviewWrap");
const imagePreview    = document.getElementById("imagePreview");
const removeImageBtn  = document.getElementById("removeImage");
const scanImageBtn    = document.getElementById("scanImageBtn");
let   selectedFile    = null;

imageInput.addEventListener("change", () => handleFile(imageInput.files[0]));

dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", e => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  handleFile(e.dataTransfer.files[0]);
});
dropZone.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") imageInput.click(); });

function handleFile(file) {
  if (!file) return;
  if (!file.type.startsWith("image/")) { showToast("Please upload an image file."); return; }
  if (file.size > 10 * 1024 * 1024)   { showToast("File exceeds 10 MB limit."); return; }
  selectedFile = file;
  const url = URL.createObjectURL(file);
  imagePreview.src = url;
  imagePreviewWrap.hidden = false;
  dropZone.hidden = true;
  scanImageBtn.disabled = false;
}

removeImageBtn.addEventListener("click", () => {
  selectedFile = null;
  imagePreview.src = "";
  imagePreviewWrap.hidden = true;
  dropZone.hidden = false;
  imageInput.value = "";
  scanImageBtn.disabled = true;
  hideResults();
});

/* ── URL examples ──────────────────────────────────────────────────────────── */
document.querySelectorAll(".example-chip").forEach(chip => {
  chip.addEventListener("click", () => {
    document.getElementById("urlInput").value = chip.dataset.url;
  });
});

/* ── Scan: Text ────────────────────────────────────────────────────────────── */
document.getElementById("scanTextBtn").addEventListener("click", async () => {
  const text = textInput.value.trim();
  if (!text) { showToast("Please paste some text to scan."); return; }

  const btn = document.getElementById("scanTextBtn");
  setLoading(btn, true);
  try {
    const data = await postJSON("/api/scan/text", { text });
    renderResults(data);
  } catch (e) {
    showToast(e.message);
  } finally {
    setLoading(btn, false);
  }
});

/* ── Scan: Image ───────────────────────────────────────────────────────────── */
document.getElementById("scanImageBtn").addEventListener("click", async () => {
  if (!selectedFile) { showToast("No image selected."); return; }

  const btn = document.getElementById("scanImageBtn");
  setLoading(btn, true);
  try {
    const formData = new FormData();
    formData.append("file", selectedFile);
    const res = await fetch(`${API_BASE}/api/scan/image`, {
      method: "POST",
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Server error" }));
      throw new Error(err.detail || err.error || "Scan failed");
    }
    const data = await res.json();
    renderResults(data);
  } catch (e) {
    showToast(e.message);
  } finally {
    setLoading(btn, false);
  }
});

/* ── Scan: URL ─────────────────────────────────────────────────────────────── */
document.getElementById("scanUrlBtn").addEventListener("click", async () => {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) { showToast("Please enter a URL to scan."); return; }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    showToast("URL must start with http:// or https://"); return;
  }

  const btn = document.getElementById("scanUrlBtn");
  setLoading(btn, true);
  try {
    const data = await postJSON("/api/scan/url", { url });
    renderResults(data);
  } catch (e) {
    showToast(e.message);
  } finally {
    setLoading(btn, false);
  }
});

/* ── Scan again ────────────────────────────────────────────────────────────── */
document.getElementById("scanAgainBtn").addEventListener("click", hideResults);

/* ── Render results ────────────────────────────────────────────────────────── */
function renderResults(data) {
  const panel = document.getElementById("resultsPanel");

  // Score + level text
  const levelText = document.getElementById("riskLevelText");
  const scoreText = document.getElementById("riskScoreText");
  const fill      = document.getElementById("riskFill");
  const track     = document.getElementById("riskTrack");
  const summary   = document.getElementById("riskSummary");

  const levelLabel = { safe: "Safe", suspicious: "Suspicious", dangerous: "Dangerous" }[data.level] || data.level;
  levelText.textContent = levelLabel;
  levelText.className   = "risk-level-text " + data.level;

  // Animate score counter
  animateCount(scoreText, 0, data.score, 900);

  // Fill bar
  const fillColor = { safe: "var(--safe)", suspicious: "var(--suspicious)", dangerous: "var(--dangerous)" }[data.level];
  fill.style.background = fillColor;
  fill.style.boxShadow  = `0 0 12px ${fillColor}55`;
  requestAnimationFrame(() => {
    setTimeout(() => { fill.style.width = data.score + "%"; }, 50);
  });

  track.setAttribute("aria-valuenow", data.score);

  summary.textContent  = data.summary;
  summary.className    = "risk-summary " + data.level;

  // Signals
  const list = document.getElementById("signalsList");
  list.innerHTML = "";

  if (!data.signals || data.signals.length === 0) {
    list.innerHTML = `<li class="no-signals"><div class="no-signals-icon">✓</div>No threat indicators found.</li>`;
  } else {
    data.signals.forEach((sig, i) => {
      const li = document.createElement("li");
      li.className = `signal-item ${sig.category}`;
      li.style.animationDelay = `${i * 60}ms`;
      li.innerHTML = `
        <span class="signal-dot" aria-hidden="true"></span>
        <span class="signal-label">${escapeHtml(sig.label)}</span>
        <span class="signal-category">${escapeHtml(sig.category)}</span>
      `;
      list.appendChild(li);
    });
  }

  // Extracted text (image scans)
  const extractedSection = document.getElementById("extractedSection");
  const extractedText    = document.getElementById("extractedText");
  if (data.extracted_text && data.extracted_text.trim()) {
    extractedText.textContent = data.extracted_text;
    extractedSection.hidden   = false;
  } else {
    extractedSection.hidden = true;
  }

  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideResults() {
  const panel = document.getElementById("resultsPanel");
  panel.hidden = true;
  document.getElementById("riskFill").style.width = "0%";
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */
async function postJSON(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Server error" }));
    throw new Error(err.detail || err.error || `Request failed (${res.status})`);
  }
  return res.json();
}

function setLoading(btn, loading) {
  btn.classList.toggle("loading", loading);
  btn.disabled = loading;
}

function animateCount(el, from, to, duration) {
  const start = performance.now();
  const update = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;");
}

let toastTimer;
function showToast(msg) {
  let toast = document.querySelector(".toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 4000);
}
