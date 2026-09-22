/* -------------------------------------------------------------
   AWS Cloud Security Misconfiguration Scanner
   Dashboard Frontend Controller
   ------------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", () => {
  const runScanBtn = document.getElementById("runScanBtn");
  const regionSelect = document.getElementById("regionSelect");

  const statusAlert = document.getElementById("statusAlert");
  const statusMessage = document.getElementById("statusMessage");
  const resultsWrapper = document.getElementById("resultsWrapper");

  // Metric fields
  const scoreValue = document.getElementById("scoreValue");
  const scoreStatusBadge = document.getElementById("scoreStatusBadge");
  const metaAccount = document.getElementById("metaAccount");
  const metaRegion = document.getElementById("metaRegion");

  const countCritical = document.getElementById("countCritical");
  const countHigh = document.getElementById("countHigh");
  const countMedium = document.getElementById("countMedium");
  const countLow = document.getElementById("countLow");
  const totalRiskPoints = document.getElementById("totalRiskPoints");
  const totalFindingsCount = document.getElementById("totalFindingsCount");

  const resBuckets = document.getElementById("resBuckets");
  const resUsers = document.getElementById("resUsers");
  const resInstances = document.getElementById("resInstances");
  const resSecurityGroups = document.getElementById("resSecurityGroups");

  // Filters and Table
  const filterSeverity = document.getElementById("filterSeverity");
  const filterService = document.getElementById("filterService");
  const searchQuery = document.getElementById("searchQuery");
  const findingsTableBody = document.getElementById("findingsTableBody");
  const noFindingsMessage = document.getElementById("noFindingsMessage");

  let currentFindings = [];

  // -----------------------------------------------------------
  // Alert Helpers
  // -----------------------------------------------------------
  function showAlert(msg, type = "danger") {
    statusAlert.className = `alert alert-${type}`;
    statusMessage.innerHTML = msg;
    statusAlert.classList.remove("d-none");
  }

  function hideAlert() {
    statusAlert.classList.add("d-none");
    statusMessage.innerHTML = "";
  }

  // -----------------------------------------------------------
  // Trigger Live Scan
  // -----------------------------------------------------------
  runScanBtn.addEventListener("click", async () => {
    const region = regionSelect.value;
    hideAlert();
    setScanningState(true, "Scanning Environment...");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ region: region })
      });

      const body = await res.json();

      if (!res.ok || !body.success) {
        if (body.credentials_missing) {
          showAlert(`
            <strong>AWS Credentials Not Found:</strong><br>
            AWS credentials were not detected in your current session or configuration.<br>
            Please configure valid AWS credentials in your terminal using <code>aws configure</code> or environment variables.
          `, "danger");
        } else {
          showAlert(`<strong>Scan Error:</strong> ${escapeHtml(body.error || "Failed to scan AWS environment.")}`, "danger");
        }
        return;
      }

      showAlert(`✓ Assessment completed successfully for region <strong>${escapeHtml(region)}</strong>`, "success");
      renderResults(body.data);

    } catch (err) {
      showAlert(`<strong>Network Error:</strong> Could not communicate with scanner server: ${err.message}`, "danger");
    } finally {
      setScanningState(false);
    }
  });

  function setScanningState(isLoading, text) {
    if (isLoading) {
      runScanBtn.disabled = true;
      runScanBtn.innerHTML = `⏳ ${text}`;
    } else {
      runScanBtn.disabled = false;
      runScanBtn.innerHTML = `<span class="btn-icon">▶</span> Run Security Scan`;
    }
  }

  // -----------------------------------------------------------
  // Render Results
  // -----------------------------------------------------------
  function renderResults(data) {
    currentFindings = data.findings || [];

    // Header & Meta
    metaAccount.textContent = data.account_id || "-";
    metaRegion.textContent = data.region || "-";

    // Score & Status
    const score = data.security_score ?? 100;
    scoreValue.textContent = score;

    scoreStatusBadge.textContent = data.assessment_status || "UNKNOWN";
    scoreStatusBadge.className = "status-pill";
    if (score >= 90) scoreStatusBadge.classList.add("status-good");
    else if (score >= 70) scoreStatusBadge.classList.add("status-moderate");
    else if (score >= 40) scoreStatusBadge.classList.add("status-needs-attention");
    else scoreStatusBadge.classList.add("status-high-risk");

    // Counters
    const summary = data.summary || {};
    countCritical.textContent = summary.critical ?? 0;
    countHigh.textContent = summary.high ?? 0;
    countMedium.textContent = summary.medium ?? 0;
    countLow.textContent = summary.low ?? 0;

    totalRiskPoints.textContent = data.total_risk ?? 0;
    totalFindingsCount.textContent = summary.total ?? currentFindings.length;

    // Audited Resources
    const res = data.resource_counts || {};
    resBuckets.textContent = res.buckets ?? 0;
    resUsers.textContent = res.users ?? 0;
    resInstances.textContent = res.instances ?? 0;
    resSecurityGroups.textContent = res.security_groups ?? 0;

    // Show Results
    resultsWrapper.classList.remove("d-none");

    // Apply Filter & Populate Table
    applyFilters();
  }

  // -----------------------------------------------------------
  // Filters & Table Rendering
  // -----------------------------------------------------------
  filterSeverity.addEventListener("change", applyFilters);
  filterService.addEventListener("change", applyFilters);
  searchQuery.addEventListener("input", applyFilters);

  function applyFilters() {
    const sev = filterSeverity.value;
    const srv = filterService.value;
    const query = searchQuery.value.trim().toLowerCase();

    const filtered = currentFindings.filter(item => {
      if (sev !== "ALL" && item.severity !== sev) return false;
      if (srv !== "ALL" && item.service !== srv) return false;
      if (query) {
        const text = `${item.resource} ${item.issue} ${item.recommendation}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    populateTable(filtered);
  }

  function populateTable(findings) {
    findingsTableBody.innerHTML = "";

    if (!findings || findings.length === 0) {
      noFindingsMessage.classList.remove("d-none");
      return;
    }

    noFindingsMessage.classList.add("d-none");

    findings.forEach((item, index) => {
      const tr = document.createElement("tr");

      const sevClass = {
        "CRITICAL": "sev-badge-critical",
        "HIGH": "sev-badge-high",
        "MEDIUM": "sev-badge-medium",
        "LOW": "sev-badge-low"
      }[item.severity] || "";

      tr.innerHTML = `
        <td><strong>${index + 1}</strong></td>
        <td><span class="service-tag">${escapeHtml(item.service || "")}</span></td>
        <td class="resource-cell">${escapeHtml(item.resource || "")}</td>
        <td>${escapeHtml(item.issue || "")}</td>
        <td><span class="sev-badge ${sevClass}">${escapeHtml(item.severity || "")}</span></td>
        <td><strong>${item.risk ?? 0}</strong></td>
        <td class="recommendation-cell">✓ ${escapeHtml(item.recommendation || "")}</td>
      `;

      findingsTableBody.appendChild(tr);
    });
  }

  function escapeHtml(str) {
    if (typeof str !== "string") return str;
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
