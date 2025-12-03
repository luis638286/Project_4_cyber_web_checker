const BACKEND_URL1 = "https://p3-website-vulnerability-checker.onrender.com/scan";
const BACKEND_URL2 = "http://127.0.0.1:5000/scan";

const BACKEND_URL = BACKEND_URL2

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const btn = document.getElementById("scan-btn");
const exportBtn = document.getElementById("export-btn");
const exportRow = document.getElementById("export-row");

let lastScanData = null;

const headerDescriptions = {
  "Content-Security-Policy":
    "Content-Security-Policy (CSP) controls which scripts can run and which resources can load.",
  "Strict-Transport-Security":
    "Strict-Transport-Security (HSTS) tells browsers to only use HTTPS for this site.",
  "X-Content-Type-Options":
    "X-Content-Type-Options prevents the browser from guessing file types.",
  "X-Frame-Options":
    "X-Frame-Options controls iframe embedding to prevent clickjacking.",
  "Referrer-Policy":
    "Referrer-Policy controls how much referrer information is shared with other sites.",
  "Permissions-Policy":
    "Permissions-Policy controls access to browser features like camera or microphone."
};

const genericHeaderDescription =
  "This header is recommended to reduce the site's attack surface.";

const otherDescriptions = {
  "https_disabled":
    "The site is served over plain HTTP. Traffic can be intercepted or modified.",
  "no_https_redirect":
    "HTTP does not redirect to HTTPS. Users may stay on an insecure connection.",
  "Missing HttpOnly":
    "Cookies missing HttpOnly can be stolen via XSS, because JavaScript can read them.",
  "Missing Secure flag":
    "Cookies missing Secure may be sent over HTTP and intercepted.",
  "https_ok": "The site uses HTTPS.",
  "https_redirect_ok": "HTTP correctly redirects to HTTPS.",
  "headers_ok": "All tracked headers are present.",
  "cookies_ok": "No cookie issues detected."
};

const fixSuggestions = {
  "https_disabled":
    "- Install an SSL/TLS certificate.\n- Configure the server to serve HTTPS.\n- Update links to use https://.",
  "no_https_redirect":
    "- Configure a 301 redirect in Nginx/Apache from http:// to https://.\n- Test that visiting http:// automatically goes to https://.",
  "Missing HttpOnly":
    "- Add HttpOnly to sensitive cookies (such as session cookies).\n- Use your framework's cookie/session settings.",
  "Missing Secure flag":
    "- Add the Secure flag to cookies so they are only sent over HTTPS.",
  "Content-Security-Policy":
    "- Add a CSP header, for example: Content-Security-Policy: default-src 'self';\n- Start with a simple policy and tighten it over time.",
  "Strict-Transport-Security":
    "- Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains.\n- Only enable after HTTPS works everywhere.",
  "X-Content-Type-Options":
    "- Add X-Content-Type-Options: nosniff.",
  "X-Frame-Options":
    "- Add X-Frame-Options: DENY or SAMEORIGIN.",
  "Referrer-Policy":
    "- Add Referrer-Policy: strict-origin-when-cross-origin.",
  "Permissions-Policy":
    "- Add a Permissions-Policy header restricting features you do not need."
};

// Risk levels for each specific issue
// Scale: None, Low, Medium, High, Critical
const riskMap = {
  // HTTPS / redirects
  "https_disabled": "Critical",
  "no_https_redirect": "High",
  "https_ok": "None",
  "https_redirect_ok": "None",

  // Missing headers
  "Content-Security-Policy": "High",
  "Strict-Transport-Security": "High",
  "X-Frame-Options": "Medium",
  "X-Content-Type-Options": "Medium",
  "Referrer-Policy": "Low",
  "Permissions-Policy": "Low",
  "headers_ok": "None",

  // Cookies
  "Missing HttpOnly": "High",
  "Missing Secure flag": "High",
  "cookies_ok": "None"
};

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  let url = urlInput.value.trim();
  if (!url) return;

  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
    urlInput.value = url;
  }

  statusEl.textContent = "Scanning...";
  statusEl.className = "status loading";
  resultsEl.style.display = "none";
  exportRow.style.display = "none";
  resultsEl.innerHTML = "";
  btn.disabled = true;

  try {
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const text = await res.text();
    let data;

    try {
      data = JSON.parse(text);
    } catch {
      throw new Error("Backend did not return JSON.");
    }

    if (!res.ok || data.error) {
      statusEl.textContent = "Error: " + (data.error || "Unknown error");
      statusEl.className = "status bad";
      btn.disabled = false;
      lastScanData = null;
      return;
    }

    lastScanData = data;

    renderResults(data);
    statusEl.textContent = "Scan completed.";
    statusEl.className = "status ok";
    exportRow.style.display = "flex";
  } catch (err) {
    statusEl.textContent = "Request failed: " + err.message;
    statusEl.className = "status bad";
    lastScanData = null;
  } finally {
    btn.disabled = false;
  }
});

// Export logic for TXT
exportBtn.addEventListener("click", () => {
  if (!lastScanData) {
    alert("No scan results to export.");
    return;
  }

  const reportText = generateTextReport(lastScanData);

  const blob = new Blob([reportText], { type: "text/plain" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;

  const safeUrl = (lastScanData.url || "scan")
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]/gi, "_");

  a.download = safeUrl + "_security_report.txt";
  a.click();

  URL.revokeObjectURL(url);
});

function generateTextReport(data) {
  const date = new Date().toLocaleString();
  let report = "WEBSITE SECURITY SCAN REPORT\n";
  report += "============================\n";
  report += "Scan Date:        " + date + "\n";
  report += "Target URL:       " + data.url + "\n";
  report += "Status Code:      " + data.status_code + "\n";
  report += "Overall Risk:     " + (data.risk_level || "Unknown") + "\n";
  report += "Security Score:   " +
    ((data.security_score !== undefined && data.security_score !== null)
      ? data.security_score
      : "N/A") + " / 100\n\n";

  report += "[1] HTTPS & CONNECTION\n";
  report += "----------------------\n";
  report += "HTTPS Enabled:      " + (data.https ? "YES (Good)" : "NO (Insecure)") + "\n";
  report += "Redirects to HTTPS: " + (data.redirects_to_https ? "YES" : "NO") + "\n";
  if (!data.https) {
    report += " -> Risk: " + getRiskLabelForKey("https_disabled") + "\n";
  }
  if (data.redirects_to_https === false) {
    report += " -> Risk for no HTTPS redirect: " +
      getRiskLabelForKey("no_https_redirect") + "\n";
  }
  report += "\n";

  report += "[2] MISSING SECURITY HEADERS\n";
  report += "----------------------------\n";
  if (data.missing_headers && data.missing_headers.length > 0) {
    data.missing_headers.forEach((h) => {
      report +=
        " [!] Missing: " +
        h +
        " (Risk: " +
        getRiskLabelForKey(h) +
        ")\n";
    });
  } else {
    report += " [OK] All tracked headers are present.\n";
  }
  report += "\n";

  report += "[3] PRESENT HEADERS\n";
  report += "-------------------\n";
  if (data.present_headers && data.present_headers.length > 0) {
    data.present_headers.forEach((h) => {
      report += " [OK] Found: " + h + "\n";
    });
  } else {
    report += " [!] No security headers found.\n";
  }
  report += "\n";

  report += "[4] COOKIES\n";
  report += "-----------\n";
  if (data.cookie_issues && data.cookie_issues.length > 0) {
    data.cookie_issues.forEach((issue) => {
      report +=
        " [!] Issue: " +
        issue +
        " (Risk: " +
        getRiskLabelForKey(issue) +
        ")\n";
    });
  } else {
    report += " [OK] No cookie configuration issues detected.\n";
  }

  report += "\n============================\n";
  report += "End of Report\n";

  return report;
}

function renderResults(data) {
  const missingHeaders = data.missing_headers || [];
  const presentHeaders = data.present_headers || [];
  const cookieIssues = data.cookie_issues || [];

  const httpsIssues = [];

  httpsIssues.push(
    data.https
      ? { key: "https_ok", label: "HTTPS enabled", severity: "ok" }
      : { key: "https_disabled", label: "HTTPS is NOT enabled", severity: "bad" }
  );

  if (data.redirects_to_https === false) {
    httpsIssues.push({
      key: "no_https_redirect",
      label: "HTTP -> HTTPS redirect: NO",
      severity: "bad"
    });
  } else if (data.redirects_to_https === true) {
    httpsIssues.push({
      key: "https_redirect_ok",
      label: "HTTP -> HTTPS redirect: YES",
      severity: "ok"
    });
  }

  const headerMissingItems = missingHeaders.length
    ? missingHeaders.map((h) => ({
        key: h,
        label: "Missing: " + h,
        severity: "bad"
      }))
    : [
        {
          key: "headers_ok",
          label: "No tracked headers are missing.",
          severity: "ok"
        }
      ];

const headerPresentItems = presentHeaders.map((h) => ({
  key: "present_" + h,  // NEW: unique key
  label: "Present: " + h,
  severity: "ok"
}));


  const cookieItems = cookieIssues.length
    ? cookieIssues.map((c) => ({ key: c, label: c, severity: "bad" }))
    : [
        {
          key: "cookies_ok",
          label: "No obvious cookie issues detected.",
          severity: "ok"
        }
      ];

  const connectionBadgeType = httpsIssues.some((i) => i.severity === "bad")
    ? "bad"
    : "ok";
  const headersBadgeType = missingHeaders.length ? "bad" : "ok";
  const cookiesBadgeType = cookieIssues.length ? "bad" : "ok";

  // Overall risk (C-style from backend)
  const riskScore =
    data.security_score !== undefined && data.security_score !== null
      ? data.security_score
      : null;
  const riskLevel = data.risk_level || "Unknown";

  const riskBadgeType =
    riskLevel === "Low"
      ? "ok"
      : riskLevel === "Medium"
      ? "neutral"
      : riskLevel === "High"
      ? "bad"
      : riskLevel === "Critical"
      ? "bad"
      : "ok";

  resultsEl.innerHTML = `
    <div class="card">
      <div class="card-header">
        <div class="card-title">Overall Risk</div>
        <span class="badge ${riskBadgeType}">
          ${escapeHtml(riskLevel)} risk
        </span>
      </div>
      <div style="font-size:0.9rem;color:#6b7280;">
        Overall security score: ${riskScore !== null ? riskScore : "N/A"} / 100
      </div>
      <p style="font-size:0.84rem;color:#6b7280;margin-top:6px;">
        This score is based on HTTPS usage, redirect behaviour, security headers and cookie protection.
        Lower scores indicate higher risk.
      </p>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Connection & HTTPS</div>
        <span class="badge ${connectionBadgeType}">
          ${connectionBadgeType === "ok" ? "Looks good" : "Issues found"}
        </span>
      </div>
      <div style="font-size:0.82rem;color:#6b7280;">
        Scanned URL: <code>${escapeHtml(data.url)}</code> · Status code: ${data.status_code}
      </div>
      <ul class="issue-list">
        ${httpsIssues.map(renderIssueItem).join("")}
      </ul>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Security Headers</div>
        <span class="badge ${headersBadgeType}">
          ${headersBadgeType === "ok" ? "All present (tracked)" : "Missing headers"}
        </span>
      </div>
      <ul class="issue-list">
        ${headerMissingItems.map(renderIssueItem).join("")}
      </ul>
      ${
        headerPresentItems.length
          ? `
        <hr style="border:none;border-top:1px solid #e5e7eb;margin:8px 0 4px;">
        <div style="font-size:0.82rem;color:#6b7280;margin-bottom:4px;">
          Headers that are already present:
        </div>
        <ul class="issue-list">
          ${headerPresentItems.map(renderIssueItem).join("")}
        </ul>`
          : ""
      }
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Cookies</div>
        <span class="badge ${cookiesBadgeType}">
          ${cookiesBadgeType === "ok" ? "No issues" : "Issues found"}
        </span>
      </div>
      <ul class="issue-list">
        ${cookieItems.map(renderIssueItem).join("")}
      </ul>
    </div>
  `;

  resultsEl.style.display = "grid";

  document.querySelectorAll(".issue-item").forEach((item) => {
    item.addEventListener("click", (ev) => {
      if (ev.target.closest(".fix-btn") || ev.target.closest(".fix-details"))
        return;
      item.classList.toggle("open");
    });
  });

  document.querySelectorAll(".fix-btn").forEach((btnEl) => {
    btnEl.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const fixBox = btnEl.nextElementSibling;
      if (fixBox) {
        fixBox.classList.toggle("open");
      }
    });
  });
}

function renderIssueItem(item) {
  const icon = item.severity === "bad" ? "⚠️" : "✔️";
  const description = getDescriptionForKey(item.key);
  const hasFix = !!fixSuggestions[item.key];

  const riskLabel = getRiskLabelForKey(item.key);

  return `
    <li class="issue-item ${item.severity}" data-key="${escapeHtml(item.key)}">
      <div class="issue-main">
        <div class="issue-label">
          <span>${icon}</span>
          <span>${escapeHtml(item.label)}</span>
        </div>
        <span style="color:#6b7280;font-size:0.8rem;">Click for details ▾</span>
      </div>
      <div style="color:#9ca3af;font-size:0.78rem;margin-top:2px;">
        Risk: ${escapeHtml(riskLabel)}
      </div>
      <div class="issue-details">
        <p>${escapeHtml(description)}</p>
        ${
          hasFix
            ? `
          <button type="button" class="fix-btn">How can I fix this?</button>
          <div class="fix-details">
            ${escapeHtml(fixSuggestions[item.key]).replace(/\n/g, "<br>")}
          </div>
        `
            : ""
        }
      </div>
    </li>
  `;
}

function getDescriptionForKey(key) {
  if (headerDescriptions[key]) return headerDescriptions[key];
  if (otherDescriptions[key]) return otherDescriptions[key];
  return genericHeaderDescription;
}

function getRiskLabelForKey(key) {
  // Any key starting with "present_" = no risk
  if (key.startsWith("present_")) {
    return "None";
  }

  // Exact match
  if (riskMap[key]) return riskMap[key];

  const lower = String(key).toLowerCase();

  // Cookie issues: substring detection
  if (lower.includes("missing httponly")) return "High";
  if (lower.includes("missing secure flag")) return "High";

  return "None";
}


function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
