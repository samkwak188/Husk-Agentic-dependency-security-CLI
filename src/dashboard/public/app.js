const feedList = document.getElementById("feed-list");
const resultsList = document.getElementById("results-list");
const connectionState = document.getElementById("connection-state");
const modal = document.getElementById("verdict-modal");
const modalTitle = document.getElementById("modal-title");
const modalSummary = document.getElementById("modal-summary");
const modalReport = document.getElementById("modal-report");
const chart = document.getElementById("results-chart");
const chartContext = chart.getContext("2d");
const template = document.getElementById("feed-item-template");

const history = [];

function verdictClass(verdict) {
  return verdict.toLowerCase();
}

function updateStats(stats) {
  document.getElementById("stat-total").textContent = String(stats.totalScanned ?? 0);
  document.getElementById("stat-malicious").textContent = String(stats.maliciousCaught ?? 0);
  document.getElementById("stat-fpr").textContent = `${Math.round((stats.falsePositiveRate ?? 0) * 100)}%`;
  document.getElementById("stat-latency").textContent = `${stats.avgScanTime ?? 0}ms`;
}

function addFeedItem(title, badgeText, badgeClass, detail) {
  const fragment = template.content.cloneNode(true);
  fragment.querySelector(".feed-package").textContent = title;
  const badge = fragment.querySelector(".badge");
  badge.textContent = badgeText;
  badge.classList.add(badgeClass);
  fragment.querySelector(".feed-detail").textContent = detail;
  fragment.querySelector(".feed-time").textContent = new Date().toLocaleTimeString();
  feedList.prepend(fragment);
  while (feedList.children.length > 20) {
    feedList.lastElementChild.remove();
  }
}

function renderResults() {
  resultsList.innerHTML = "";
  for (const verdict of history.slice(0, 12)) {
    const detail =
      verdict.verdict === "CLEAN"
        ? verdict.policy?.summary ?? verdict.reasons?.[0]?.evidence ?? verdict.narrative ?? "No summary available."
        : verdict.recommendations?.[0] ?? verdict.reasons?.[0]?.evidence ?? verdict.narrative ?? "No summary available.";
    const article = document.createElement("article");
    article.className = "result-card";
    article.innerHTML = `
      <div class="result-head">
        <strong>${verdict.packageName}@${verdict.packageVersion}</strong>
        <span class="badge ${verdictClass(verdict.verdict)}">${verdict.verdict}</span>
      </div>
      <p class="result-detail">${detail}</p>
    `;
    article.addEventListener("click", () => showModal(verdict));
    resultsList.append(article);
  }
  drawChart();
}

function drawChart() {
  const counts = {
    CLEAN: history.filter((entry) => entry.verdict === "CLEAN").length,
    SUSPICIOUS: history.filter((entry) => entry.verdict === "SUSPICIOUS").length,
    MALICIOUS: history.filter((entry) => entry.verdict === "MALICIOUS").length
  };

  const entries = [
    { label: "Clean", value: counts.CLEAN, color: "#00ff88" },
    { label: "Suspicious", value: counts.SUSPICIOUS, color: "#ffaa00" },
    { label: "Malicious", value: counts.MALICIOUS, color: "#ff3b3b" }
  ];
  const max = Math.max(1, ...entries.map((entry) => entry.value));

  chartContext.clearRect(0, 0, chart.width, chart.height);
  chartContext.fillStyle = "rgba(255,255,255,0.05)";
  chartContext.fillRect(0, 0, chart.width, chart.height);

  entries.forEach((entry, index) => {
    const x = 50 + index * 140;
    const height = (entry.value / max) * 120;
    const y = 180 - height;
    chartContext.fillStyle = entry.color;
    chartContext.fillRect(x, y, 72, height);
    chartContext.fillStyle = "#f8f8fb";
    chartContext.font = "600 14px Inter";
    chartContext.fillText(entry.label, x, 204);
    chartContext.fillText(String(entry.value), x + 22, y - 10);
  });
}

function showModal(verdict) {
  modalTitle.textContent = `${verdict.verdict} - ${verdict.packageName}@${verdict.packageVersion}`;
  const reasonMarkup = (verdict.reasons || [])
    .slice(0, 6)
    .map((reason) => `<p>[${reason.severity}] ${reason.title}: ${reason.evidence}</p>`)
    .join("");
  const policyMarkup = verdict.policy ? `<p class="modal-action">Policy: ${verdict.policy.action} - ${verdict.policy.summary}</p>` : "";
  const recommendationMarkup = (verdict.recommendations || [])
    .slice(0, 4)
    .map((recommendation) => `<p class="modal-action">Action: ${recommendation}</p>`)
    .join("");
  modalSummary.innerHTML = `${policyMarkup}${reasonMarkup}${recommendationMarkup}`;
  modalReport.textContent = verdict.advisory ?? verdict.narrative ?? "No report available.";
  modal.showModal();
}

async function loadInitialResults() {
  const response = await fetch("/api/results");
  const payload = await response.json();
  updateStats(payload.stats);
  history.splice(0, history.length, ...(payload.history || []));
  renderResults();
}

function connectStream() {
  const source = new EventSource("/api/stream");
  connectionState.textContent = "live";

  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);

    if (payload.type === "stats") {
      updateStats(payload.payload);
      return;
    }

    if (payload.type === "scan:result") {
      history.unshift(payload.payload);
      renderResults();
      addFeedItem(
        `${payload.payload.packageName}@${payload.payload.packageVersion}`,
        payload.payload.verdict,
        verdictClass(payload.payload.verdict),
        payload.payload.policy?.summary ?? payload.payload.reasons?.[0]?.evidence ?? payload.payload.narrative ?? "Scan complete."
      );
      if (payload.payload.verdict === "MALICIOUS") {
        showModal(payload.payload);
      }
      return;
    }

    if (payload.type?.startsWith("scan:")) {
      const detail = payload.payload?.reason || payload.payload?.message || "Pipeline event";
      addFeedItem(payload.packageSpec, payload.type.replace("scan:", ""), "badge-live", detail);
    }
  };

  source.onerror = () => {
    connectionState.textContent = "reconnecting";
  };
}

document.getElementById("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const packageSpec = document.getElementById("package-input").value.trim();
  const forceSandbox = document.getElementById("sandbox-toggle").checked;
  if (!packageSpec) {
    return;
  }

  await fetch("/api/scan", {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({ packageSpec, forceSandbox })
  });
  document.getElementById("package-input").value = "";
});

document.getElementById("modal-close").addEventListener("click", () => modal.close());
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    modal.close();
  }
});

await loadInitialResults();
connectStream();
