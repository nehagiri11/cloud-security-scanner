let lastIssues = [];
let lastCloud = "AWS";
let lastFileName = "sample.yaml";
let findingsChart;
const HISTORY_KEY = "cloudScannerHistory";

const sampleConfig = {
    public_access: true,
    role: "admin",
    encryption: false,
    mfa_enabled: false,
    logging_enabled: false,
    password_policy: {
        min_length: 6
    },
    firewall: [
        { port: 22, cidr: "0.0.0.0/0" },
        { port: 3389, cidr: "0.0.0.0/0" }
    ]
};

document.getElementById("scanBtn").addEventListener("click", scanFile);
document.getElementById("sampleBtn").addEventListener("click", loadSampleData);
document.getElementById("pdfBtn").addEventListener("click", downloadPDF);
document.getElementById("jsonBtn").addEventListener("click", exportJSON);
document.getElementById("severityFilter").addEventListener("change", renderFilteredResults);
document.getElementById("searchInput").addEventListener("input", renderFilteredResults);

function scanFile() {
    const file = document.getElementById("fileInput").files[0];
    const cloud = document.getElementById("cloudType").value;

    if (!file) {
        alert("Please upload a JSON or YAML configuration file.");
        return;
    }

    const reader = new FileReader();

    reader.onload = function(event) {
        try {
            const config = parseConfig(file.name, event.target.result);
            runFullScan(config, cloud, file.name);
        } catch (error) {
            alert(error.message || "Invalid configuration file.");
        }
    };

    reader.readAsText(file);
}

function loadSampleData() {
    const cloud = document.getElementById("cloudType").value;
    runFullScan(sampleConfig, cloud, "sample.yaml");
}

function parseConfig(fileName, rawContent) {
    const lower = fileName.toLowerCase();

    if (lower.endsWith(".yaml") || lower.endsWith(".yml")) {
        return jsyaml.load(rawContent);
    }

    if (lower.endsWith(".json")) {
        return JSON.parse(rawContent);
    }

    throw new Error("Only JSON, YAML, and YML files are supported.");
}

function runFullScan(config, cloud, fileName) {
    const issues = runScan(config, cloud);
    lastIssues = issues;
    lastCloud = cloud;
    lastFileName = fileName;

    renderFilteredResults();
    updateSummary(issues, cloud, fileName);
    drawChart(issues);
    updateRecommendations(issues);
    saveHistory(issues, cloud, fileName);
    renderHistory();
}

function runScan(config, cloud) {
    const issues = [];

    if (config.public_access === true) {
        const issueTitle = cloud === "AWS"
            ? "Public S3 bucket exposure"
            : cloud === "Azure"
                ? "Public blob storage exposure"
                : "Public cloud storage exposure";

        issues.push(makeIssue(
            issueTitle,
            "High",
            "Storage",
            "Disable public access and enforce private bucket or container policies.",
            "Audit all externally reachable storage resources and restrict them to approved identities only."
        , ["CIS", "NIST AC-3"]));
    }

    if (Array.isArray(config.firewall)) {
        config.firewall.forEach(rule => {
            if (rule.cidr === "0.0.0.0/0" && [22, 3389, 3306, 5432].includes(Number(rule.port))) {
                issues.push(makeIssue(
                    `Sensitive port ${rule.port} exposed to the internet`,
                    "Critical",
                    "Network",
                    "Restrict inbound CIDR ranges or place the service behind VPN or bastion access.",
                    "Open administrative ports are high-value entry points; apply least exposure and segment management traffic."
                , ["CIS", "NIST SC-7"]));
            }
        });
    }

    if (typeof config.role === "string" && ["admin", "owner", "root"].includes(config.role.toLowerCase())) {
        issues.push(makeIssue(
            "Privileged identity role assigned",
            "Medium",
            "Identity",
            "Replace broad administrative roles with least-privilege access assignments.",
            "Break large permissions into task-based roles and review privileged assignments regularly."
        , ["NIST AC-6", "ISO 27001"]));
    }

    if (config.encryption === false) {
        issues.push(makeIssue(
            "Encryption at rest disabled",
            "High",
            "Data Protection",
            "Enable encryption for storage volumes, databases, and backups.",
            "Use provider-managed or customer-managed keys for persistent storage and verify encryption defaults."
        , ["NIST SC-28", "PCI DSS"]));
    }

    if (config.mfa_enabled === false) {
        issues.push(makeIssue(
            "Multi-factor authentication disabled",
            "High",
            "Identity",
            "Require MFA for privileged users and console access.",
            "MFA should be mandatory for all administrator accounts to reduce account takeover risk."
        , ["CIS", "NIST IA-2"]));
    }

    if (config.logging_enabled === false) {
        issues.push(makeIssue(
            "Audit logging disabled",
            "Medium",
            "Monitoring",
            "Enable activity logging and retain logs for investigation and compliance.",
            "Centralized logs improve detection, forensics, and change-tracking across providers."
        , ["NIST AU-2", "ISO 27001"]));
    }

    if (config.password_policy && Number(config.password_policy.min_length) < 12) {
        issues.push(makeIssue(
            "Weak password policy",
            "Medium",
            "Identity",
            "Increase minimum password length and enforce stronger authentication controls.",
            "Combine longer passwords with MFA and credential rotation for better account security."
        , ["CIS", "NIST IA-5"]));
    }

    if (cloud === "AWS" && config.versioning_enabled === false) {
        issues.push(makeIssue(
            "S3 versioning disabled",
            "Medium",
            "Storage",
            "Enable bucket versioning for recovery and rollback support.",
            "Versioning improves resilience against accidental deletion and ransomware-style modification.",
            ["AWS Well-Architected", "CIS"]
        ));
    }

    if (cloud === "Azure" && config.defender_enabled === false) {
        issues.push(makeIssue(
            "Microsoft Defender for Cloud disabled",
            "High",
            "Monitoring",
            "Enable Defender for Cloud recommendations and alerts.",
            "Built-in cloud security posture management improves visibility into Azure misconfigurations.",
            ["Azure Security Benchmark", "CIS"]
        ));
    }

    if (cloud === "GCP" && config.audit_config === false) {
        issues.push(makeIssue(
            "Cloud audit configuration disabled",
            "High",
            "Monitoring",
            "Enable Cloud Audit Logs for administrative and data access events.",
            "Audit visibility is essential for incident investigation and compliance in GCP projects.",
            ["Google Cloud Security Foundations", "NIST AU-12"]
        ));
    }

    if (issues.length === 0) {
        issues.push(makeIssue(
            "No major misconfigurations detected",
            "Safe",
            "Posture",
            "No immediate action required.",
            "Continue continuous monitoring because secure posture can drift over time.",
            ["Best Practice"]
        ));
    }

    return issues;
}

function makeIssue(issue, severity, category, fix, ai, compliance) {
    return { issue, severity, category, fix, ai, compliance };
}

function displayResults(issues) {
    const tbody = document.querySelector("#resultTable tbody");
    tbody.innerHTML = "";

    issues.forEach(item => {
        const row = tbody.insertRow();
        row.insertCell(0).innerText = item.issue;

        const severityCell = row.insertCell(1);
        severityCell.innerHTML = `<span class="severity-pill ${item.severity.toLowerCase()}">${item.severity}</span>`;

        row.insertCell(2).innerText = item.category;
        row.insertCell(3).innerText = item.compliance.join(", ");
        row.insertCell(4).innerText = item.fix;
        row.insertCell(5).innerText = item.ai;
    });
}

function renderFilteredResults() {
    const severity = document.getElementById("severityFilter").value;
    const query = document.getElementById("searchInput").value.trim().toLowerCase();

    const filtered = lastIssues.filter(item => {
        const matchesSeverity = severity === "All" || item.severity === severity;
        const matchesQuery = !query ||
            item.issue.toLowerCase().includes(query) ||
            item.category.toLowerCase().includes(query) ||
            item.compliance.join(" ").toLowerCase().includes(query);
        return matchesSeverity && matchesQuery;
    });

    displayResults(filtered);
}

function updateSummary(issues, cloud, fileName) {
    const score = calculateRiskScore(issues);
    const counts = countBySeverity(issues);
    const hasRealFindings = issues.some(item => item.severity !== "Safe");
    const posture = getPostureLabel(score, hasRealFindings);

    document.getElementById("riskHeadline").innerText = posture.headline;
    document.getElementById("riskBadge").innerText = posture.badge;
    document.getElementById("riskBadge").className = `badge ${posture.className}`;
    document.getElementById("riskScore").innerText = `${score}%`;
    document.getElementById("scoreDescription").innerText = posture.description;
    document.getElementById("totalFindings").innerText = hasRealFindings ? counts.total : 0;
    document.getElementById("criticalCount").innerText = counts.Critical;
    document.getElementById("highCount").innerText = counts.High;
    document.getElementById("mediumCount").innerText = counts.Medium;
    document.getElementById("scanMeta").innerText = `Scanned ${fileName} for ${cloud} on ${new Date().toLocaleString()}.`;
}

function calculateRiskScore(issues) {
    const weight = {
        Critical: 35,
        High: 25,
        Medium: 12,
        Safe: 0
    };

    return Math.min(
        100,
        issues.reduce((sum, issue) => sum + (weight[issue.severity] || 0), 0)
    );
}

function countBySeverity(issues) {
    const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Safe: 0,
        total: 0
    };

    issues.forEach(issue => {
        if (counts[issue.severity] !== undefined) {
            counts[issue.severity] += 1;
        }
        if (issue.severity !== "Safe") {
            counts.total += 1;
        }
    });

    return counts;
}

function getPostureLabel(score, hasRealFindings) {
    if (!hasRealFindings) {
        return {
            headline: "Configuration appears stable",
            badge: "Low Risk",
            className: "safe",
            description: "No major issues were found in the current scan, but periodic reassessment is still recommended."
        };
    }

    if (score >= 70) {
        return {
            headline: "Critical security exposure detected",
            badge: "Critical",
            className: "critical",
            description: "Immediate remediation is recommended because the environment contains severe and externally exploitable weaknesses."
        };
    }

    if (score >= 40) {
        return {
            headline: "Elevated cloud security risk",
            badge: "High Risk",
            className: "high",
            description: "The configuration contains important gaps that should be prioritized before deployment or production use."
        };
    }

    return {
        headline: "Moderate posture concerns found",
        badge: "Moderate",
        className: "medium",
        description: "The environment is not critically exposed, but several security controls should be strengthened."
    };
}

function drawChart(issues) {
    const counts = countBySeverity(issues);
    const chartCanvas = document.getElementById("chart");

    if (findingsChart) {
        findingsChart.destroy();
    }

    findingsChart = new Chart(chartCanvas, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium"],
            datasets: [
                {
                    label: "Findings",
                    data: [counts.Critical, counts.High, counts.Medium],
                    backgroundColor: ["#b42318", "#d92d20", "#f79009"],
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

function updateRecommendations(issues) {
    const container = document.getElementById("recommendationList");
    const realIssues = issues.filter(issue => issue.severity !== "Safe");

    if (!realIssues.length) {
        container.innerHTML = `
            <article class="recommendation-card">
                <span class="priority-tag priority-plan">Maintain</span>
                <h3>Continue continuous monitoring</h3>
                <p>The current scan looks healthy. Keep reviewing identity, logging, and network exposure regularly to avoid security drift.</p>
            </article>
        `;
        return;
    }

    const grouped = [
        {
            title: "Fix critical internet exposure first",
            priority: "priority-now",
            label: "Immediate",
            matches: realIssues.filter(issue => issue.severity === "Critical")
        },
        {
            title: "Harden access controls and data protection",
            priority: "priority-soon",
            label: "Next",
            matches: realIssues.filter(issue => issue.severity === "High")
        },
        {
            title: "Improve baseline governance controls",
            priority: "priority-plan",
            label: "Planned",
            matches: realIssues.filter(issue => issue.severity === "Medium")
        }
    ].filter(group => group.matches.length);

    container.innerHTML = grouped.map(group => `
        <article class="recommendation-card">
            <span class="priority-tag ${group.priority}">${group.label}</span>
            <h3>${group.title}</h3>
            <p>${group.matches.slice(0, 3).map(item => item.issue).join("; ")}.</p>
        </article>
    `).join("");
}

function saveHistory(issues, cloud, fileName) {
    const score = calculateRiskScore(issues);
    const existing = getHistory();
    existing.unshift({
        cloud,
        fileName,
        score,
        findings: issues.filter(issue => issue.severity !== "Safe").length,
        timestamp: new Date().toLocaleString()
    });

    localStorage.setItem(HISTORY_KEY, JSON.stringify(existing.slice(0, 5)));
}

function getHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch {
        return [];
    }
}

function renderHistory() {
    const container = document.getElementById("historyList");
    const items = getHistory();

    if (!items.length) {
        container.innerHTML = `
            <article class="history-card">
                <h3>No scans saved yet</h3>
                <p>Your recent scan results will appear here after the first analysis.</p>
            </article>
        `;
        return;
    }

    container.innerHTML = items.map(item => `
        <article class="history-card">
            <h3>${item.cloud} scan on ${item.fileName}</h3>
            <span class="mini-badge">Risk ${item.score}%</span>
            <span class="mini-badge">${item.findings} findings</span>
            <p class="history-meta">${item.timestamp}</p>
        </article>
    `).join("");
}

function downloadPDF() {
    if (!lastIssues.length) {
        alert("Run a scan before downloading a report.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const score = calculateRiskScore(lastIssues);

    doc.setFontSize(18);
    doc.text("Cloud Security Misconfiguration Report", 20, 20);

    doc.setFontSize(11);
    doc.text(`Cloud Provider: ${lastCloud}`, 20, 32);
    doc.text(`Configuration File: ${lastFileName}`, 20, 40);
    doc.text(`Risk Score: ${score}%`, 20, 48);

    let y = 62;
    lastIssues.forEach((issue, index) => {
        const lines = doc.splitTextToSize(
            `${index + 1}. ${issue.issue} | ${issue.severity} | ${issue.category}
Fix: ${issue.fix}
Suggestion: ${issue.ai}`,
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

function exportJSON() {
    if (!lastIssues.length) {
        alert("Run a scan before exporting results.");
        return;
    }

    const payload = {
        cloud: lastCloud,
        fileName: lastFileName,
        generatedAt: new Date().toISOString(),
        riskScore: calculateRiskScore(lastIssues),
        findings: lastIssues
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "cloud-security-report.json";
    link.click();
    URL.revokeObjectURL(link.href);
}

renderHistory();
loadSampleData();
