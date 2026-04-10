const TOKEN_KEY = "cloud_scanner_token";
const USER_KEY = "cloud_scanner_user";

let lastFindings = [];
let lastCloud = "AWS";
let lastFileName = "sample.yaml";
let lastMetadata = null;
let chartInstance;

const sampleConfig = {
    public_access: true,
    block_public_access: false,
    encryption: false,
    kms_rotation_enabled: false,
    role: "admin",
    mfa_enabled: false,
    root_user_active: true,
    logging_enabled: false,
    alerting_enabled: false,
    flow_logs_enabled: false,
    backup_enabled: false,
    secret_rotation_enabled: false,
    versioning_enabled: false,
    cloudtrail_enabled: false,
    imdsv2_required: false,
    rds_public_access: true,
    password_policy: {
        min_length: 8,
        require_symbols: false
    },
    firewall: [
        { port: 22, cidr: "0.0.0.0/0" },
        { port: 5432, cidr: "0.0.0.0/0" },
        { port: 443, cidr: "0.0.0.0/0", tls: false }
    ]
};

boot();

async function boot() {
    const token = getToken();
    if (!token) {
        window.location.href = "/";
        return;
    }

    bindEvents();
    await loadSession();
    await loadHistory();
}

function bindEvents() {
    document.getElementById("scanBtn").addEventListener("click", handleScan);
    document.getElementById("sampleBtn").addEventListener("click", handleSampleScan);
    document.getElementById("awsLiveScanBtn").addEventListener("click", handleAwsLiveScan);
    document.getElementById("logoutBtn").addEventListener("click", logout);
    document.getElementById("pdfBtn").addEventListener("click", downloadPDF);
    document.getElementById("jsonBtn").addEventListener("click", exportJSON);
    document.getElementById("severityFilter").addEventListener("change", renderFilteredResults);
    document.getElementById("searchInput").addEventListener("input", renderFilteredResults);
}

async function loadSession() {
    try {
        const data = await apiFetch("/api/session");
        document.getElementById("userName").textContent = data.user.name;
        document.getElementById("userRole").textContent = data.user.role;
        localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    } catch {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        window.location.href = "/";
    }
}

async function loadHistory() {
    const container = document.getElementById("historyList");

    try {
        const data = await apiFetch("/api/history");
        if (!data.items.length) {
            container.innerHTML = `
                <article class="history-card">
                    <h3>No server scans yet</h3>
                    <p>Your backend scan history will appear here after the first scan.</p>
                </article>
            `;
            return;
        }

        container.innerHTML = data.items.map(item => `
            <article class="history-card">
                <h3>${item.cloud} scan on ${item.fileName}</h3>
                <span class="mini-badge dark-badge">Risk ${item.riskScore}%</span>
                <span class="mini-badge dark-badge">${item.findingsCount} findings</span>
                <p class="history-meta">${new Date(item.scannedAt).toLocaleString()}</p>
            </article>
        `).join("");
    } catch (error) {
        container.innerHTML = `
            <article class="history-card">
                <h3>History unavailable</h3>
                <p>${error.message}</p>
            </article>
        `;
    }
}

async function handleScan() {
    const file = document.getElementById("fileInput").files[0];
    const cloud = document.getElementById("cloudType").value;

    if (!file) {
        alert("Please upload a JSON or YAML configuration file.");
        return;
    }

    const rawContent = await file.text();

    try {
        const config = parseConfig(file.name, rawContent);
        await submitScan(config, cloud, file.name);
    } catch (error) {
        alert(error.message || "Invalid configuration file.");
    }
}

async function handleSampleScan() {
    const cloud = document.getElementById("cloudType").value;
    await submitScan(sampleConfig, cloud, "sample.yaml");
}

async function handleAwsLiveScan() {
    const message = document.getElementById("awsLiveScanMessage");
    const region = document.getElementById("awsRegion").value.trim() || "ap-south-1";
    const accessKeyId = document.getElementById("awsAccessKeyId").value.trim();
    const secretAccessKey = document.getElementById("awsSecretAccessKey").value.trim();
    const sessionToken = document.getElementById("awsSessionToken").value.trim();

    message.textContent = "Connecting to AWS and collecting live security posture data...";

    try {
        const result = await apiFetch("/api/aws/live-scan", {
            method: "POST",
            body: JSON.stringify({
                region,
                accessKeyId,
                secretAccessKey,
                sessionToken
            })
        });

        lastFindings = result.findings;
        lastCloud = result.cloud;
        lastFileName = result.fileName;
        lastMetadata = result.metadata || null;

        updateSummary(result);
        updateRecommendations(result.findings);
        updateComplianceSummary(result.findings);
        drawChart(result.summary);
        renderFilteredResults();
        await loadHistory();

        message.textContent = `Live AWS scan completed for account ${result.metadata?.accountId || "connected account"} in ${result.metadata?.region || region}.`;
    } catch (error) {
        message.textContent = error.message;
    }
}

function parseConfig(fileName, content) {
    const lower = fileName.toLowerCase();

    if (lower.endsWith(".yaml") || lower.endsWith(".yml")) {
        return jsyaml.load(content);
    }

    if (lower.endsWith(".json")) {
        return JSON.parse(content);
    }

    throw new Error("Only JSON, YAML, and YML files are supported.");
}

async function submitScan(config, cloud, fileName) {
    const result = await apiFetch("/api/scan", {
        method: "POST",
        body: JSON.stringify({ cloud, config, fileName })
    });

    lastFindings = result.findings;
    lastCloud = result.cloud;
    lastFileName = result.fileName;
    lastMetadata = result.metadata || null;

    updateSummary(result);
    updateRecommendations(result.findings);
    updateComplianceSummary(result.findings);
    drawChart(result.summary);
    renderFilteredResults();
    await loadHistory();
}

function updateSummary(result) {
    const { riskScore, summary, cloud, fileName } = result;
    const hasRealFindings = result.findings.some(item => item.severity !== "Safe");
    const posture = getPostureLabel(riskScore, hasRealFindings);
    const metaLine = result.metadata?.liveScan
        ? `Live AWS scan for account ${result.metadata.accountId} (${result.metadata.region}) on ${new Date().toLocaleString()}.`
        : `Scanned ${fileName} for ${cloud} on ${new Date().toLocaleString()}.`;

    document.getElementById("riskHeadline").textContent = posture.headline;
    document.getElementById("riskBadge").textContent = posture.badge;
    document.getElementById("riskBadge").className = `badge ${posture.className}`;
    document.getElementById("riskScore").textContent = `${riskScore}%`;
    document.getElementById("scoreDescription").textContent = posture.description;
    document.getElementById("totalFindings").textContent = result.findings.filter(item => item.severity !== "Safe").length;
    document.getElementById("criticalCount").textContent = summary.Critical || 0;
    document.getElementById("highCount").textContent = summary.High || 0;
    document.getElementById("mediumCount").textContent = summary.Medium || 0;
    document.getElementById("scanMeta").textContent = metaLine;
    updateIntelRail(result);
}

function updateIntelRail(result) {
    const actionable = result.findings.filter(item => item.severity !== "Safe");
    const categoryCounts = actionable.reduce((acc, item) => {
        acc[item.category] = (acc[item.category] || 0) + 1;
        return acc;
    }, {});
    const topCategory = Object.entries(categoryCounts)
        .sort((a, b) => b[1] - a[1])[0];

    const scanModeValue = document.getElementById("scanModeValue");
    const scanModeHint = document.getElementById("scanModeHint");
    const topCategoryValue = document.getElementById("topCategoryValue");
    const topCategoryHint = document.getElementById("topCategoryHint");

    if (result.metadata?.liveScan) {
        scanModeValue.textContent = "Live AWS posture scan";
        scanModeHint.textContent = `Connected account ${result.metadata.accountId || "unknown"} in ${result.metadata.region || "configured region"}.`;
    } else {
        scanModeValue.textContent = `${result.cloud} file assessment`;
        scanModeHint.textContent = `Analyzed ${result.fileName} through the backend rule engine.`;
    }

    if (!topCategory) {
        topCategoryValue.textContent = "No active gaps";
        topCategoryHint.textContent = "The current scan did not trigger any major controls in the active rule set.";
        return;
    }

    topCategoryValue.textContent = `${topCategory[0]} (${topCategory[1]})`;
    topCategoryHint.textContent = `Most findings in this report belong to ${topCategory[0].toLowerCase()} controls and should be prioritized in remediation.`;
}

function getPostureLabel(score, hasRealFindings) {
    if (!hasRealFindings) {
        return {
            headline: "Configuration appears stable",
            badge: "Low Risk",
            className: "safe",
            description: "No major issues were detected against the current backend rule set."
        };
    }

    if (score >= 75) {
        return {
            headline: "Critical cloud exposure detected",
            badge: "Critical",
            className: "critical",
            description: "The environment contains severe exposure points and should be remediated before deployment."
        };
    }

    if (score >= 45) {
        return {
            headline: "Elevated security risk detected",
            badge: "High Risk",
            className: "high",
            description: "Multiple serious misconfigurations were found in identity, storage, or network controls."
        };
    }

    return {
        headline: "Moderate posture gaps found",
        badge: "Moderate",
        className: "medium",
        description: "The cloud posture is not critically exposed, but baseline controls should be strengthened."
    };
}

function updateRecommendations(findings) {
    const container = document.getElementById("recommendationList");
    const realFindings = findings.filter(item => item.severity !== "Safe");

    if (!realFindings.length) {
        container.innerHTML = `
            <article class="recommendation-card">
                <span class="priority-tag priority-plan">Maintain</span>
                <h3>Maintain preventive controls</h3>
                <p>The current scan passed the configured rule set. Continue scheduled reviews, logging validation, and policy drift detection.</p>
            </article>
        `;
        return;
    }

    const groups = [
        {
            label: "Immediate",
            title: "Close internet-facing critical exposure",
            className: "priority-now",
            items: realFindings.filter(item => item.severity === "Critical")
        },
        {
            label: "Next",
            title: "Harden identity, storage, and monitoring",
            className: "priority-soon",
            items: realFindings.filter(item => item.severity === "High")
        },
        {
            label: "Planned",
            title: "Improve governance and operational resilience",
            className: "priority-plan",
            items: realFindings.filter(item => ["Medium", "Low"].includes(item.severity))
        }
    ].filter(group => group.items.length);

    container.innerHTML = groups.map(group => `
        <article class="recommendation-card">
            <span class="priority-tag ${group.className}">${group.label}</span>
            <h3>${group.title}</h3>
            <p>${group.items.slice(0, 4).map(item => item.issue).join("; ")}.</p>
        </article>
    `).join("");
}

function updateComplianceSummary(findings) {
    const container = document.getElementById("complianceSummary");
    const summary = getComplianceSummary(findings);

    if (!summary.length) {
        container.innerHTML = `
            <article class="compliance-card">
                <h3>No compliance gaps yet</h3>
                <p class="section-copy">Run a scan to map findings to frameworks such as CIS, NIST, PCI DSS, and ISO 27001.</p>
            </article>
        `;
        return;
    }

    container.innerHTML = summary.map(item => `
        <article class="compliance-card">
            <h3>${item.framework}</h3>
            <div class="compliance-stat">${item.count}</div>
            <p class="section-copy">Mapped findings in the current report reference this framework.</p>
        </article>
    `).join("");
}

function getComplianceSummary(findings) {
    const counts = new Map();

    findings
        .filter(item => item.severity !== "Safe")
        .forEach(item => {
            item.compliance.forEach(tag => {
                counts.set(tag, (counts.get(tag) || 0) + 1);
            });
        });

    return Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4)
        .map(([framework, count]) => ({ framework, count }));
}

function drawChart(summary) {
    const canvas = document.getElementById("chart");
    const emptyState = document.getElementById("chartEmptyState");
    const total =
        (summary.Critical || 0) +
        (summary.High || 0) +
        (summary.Medium || 0) +
        (summary.Low || 0);

    if (chartInstance) {
        chartInstance.destroy();
    }

    if (total === 0) {
        canvas.style.display = "none";
        emptyState.style.display = "flex";
        return;
    }

    canvas.style.display = "block";
    emptyState.style.display = "none";

    chartInstance = new Chart(canvas, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [
                {
                    label: "Findings",
                    data: [
                        summary.Critical || 0,
                        summary.High || 0,
                        summary.Medium || 0,
                        summary.Low || 0
                    ],
                    backgroundColor: ["#b42318", "#d92d20", "#f79009", "#1d4ed8"],
                    borderRadius: 12
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

function renderFilteredResults() {
    const severity = document.getElementById("severityFilter").value;
    const query = document.getElementById("searchInput").value.trim().toLowerCase();
    const filtered = lastFindings.filter(item => {
        const severityMatch = severity === "All" || item.severity === severity;
        const queryMatch = !query ||
            item.issue.toLowerCase().includes(query) ||
            item.category.toLowerCase().includes(query) ||
            item.compliance.join(" ").toLowerCase().includes(query);
        return severityMatch && queryMatch;
    });

    const tbody = document.querySelector("#resultTable tbody");
    tbody.innerHTML = "";

    filtered.forEach(item => {
        const row = tbody.insertRow();
        row.insertCell(0).textContent = item.issue;
        const severityCell = row.insertCell(1);
        severityCell.innerHTML = `<span class="severity-pill ${item.severity.toLowerCase()}">${item.severity}</span>`;
        row.insertCell(2).textContent = item.category;
        row.insertCell(3).textContent = item.compliance.join(", ");
        row.insertCell(4).textContent = item.fix;
        row.insertCell(5).textContent = item.ai;
    });
}

function downloadPDF() {
    if (!lastFindings.length) {
        alert("Run a scan before downloading a PDF report.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const severitySummary = summarizeSeverity(lastFindings);
    const complianceSummary = getComplianceSummary(lastFindings);

    doc.setFontSize(18);
    doc.text("Cloud Security Misconfiguration Report", 20, 20);
    doc.setFontSize(11);
    doc.text(`Cloud Provider: ${lastCloud}`, 20, 32);
    doc.text(`Configuration File: ${lastFileName}`, 20, 40);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 48);
    const summaryY = lastMetadata?.accountId ? 64 : 56;
    const complianceY = lastMetadata?.accountId ? 72 : 64;
    if (lastMetadata?.accountId) {
        doc.text(`AWS Account: ${lastMetadata.accountId} | Region: ${lastMetadata.region}`, 20, 56);
    }
    doc.text(`Findings Summary: Critical ${severitySummary.Critical}, High ${severitySummary.High}, Medium ${severitySummary.Medium}, Low ${severitySummary.Low}`, 20, summaryY);
    doc.text(`Top Compliance Tags: ${complianceSummary.map(item => `${item.framework} (${item.count})`).join(", ") || "None"}`, 20, complianceY);

    let y = lastMetadata?.accountId ? 86 : 78;
    lastFindings.forEach((finding, index) => {
        const lines = doc.splitTextToSize(
            `${index + 1}. ${finding.issue} | ${finding.severity} | ${finding.category}
Compliance: ${finding.compliance.join(", ")}
Fix: ${finding.fix}
Suggestion: ${finding.ai}`,
            170
        );

        if (y + lines.length * 7 > 280) {
            doc.addPage();
            y = 20;
        }

        doc.text(lines, 20, y);
        y += lines.length * 7 + 4;
    });

    doc.save("cloud-security-report.pdf");
}

function summarizeSeverity(findings) {
    return findings.reduce((acc, item) => {
        acc[item.severity] = (acc[item.severity] || 0) + 1;
        return acc;
    }, { Critical: 0, High: 0, Medium: 0, Low: 0, Safe: 0 });
}

function exportJSON() {
    if (!lastFindings.length) {
        alert("Run a scan before exporting results.");
        return;
    }

    const payload = {
        cloud: lastCloud,
        fileName: lastFileName,
        generatedAt: new Date().toISOString(),
        metadata: lastMetadata,
        findings: lastFindings
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "cloud-security-report.json";
    link.click();
    URL.revokeObjectURL(link.href);
}

async function logout() {
    try {
        await apiFetch("/api/logout", { method: "POST" });
    } catch {
        // Ignore logout API errors and still clear local auth state.
    }

    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = "/";
}

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

async function apiFetch(url, options = {}) {
    const response = await fetch(url, {
        method: options.method || "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${getToken()}`
        },
        body: options.body
    });

    const contentType = response.headers.get("content-type") || "";
    const rawText = await response.text();
    let data = {};

    if (!contentType.includes("application/json")) {
        throw new Error("The server returned a non-JSON response. Please refresh and try again.");
    }

    try {
        data = rawText ? JSON.parse(rawText) : {};
    } catch {
        throw new Error("The server returned invalid JSON. Please refresh and try again.");
    }

    if (!response.ok) {
        throw new Error(data.error || "Request failed");
    }

    return data;
}
