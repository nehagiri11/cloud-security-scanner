"use strict";

function scanConfiguration(config, cloud) {
    const provider = String(cloud || "").toUpperCase();
    const issues = [];

    const addIssue = (issue, severity, category, fix, ai, compliance) => {
        issues.push({ issue, severity, category, fix, ai, compliance });
    };

    if (config.public_access === true) {
        addIssue(
            provider === "AWS" ? "Public S3 bucket exposure" : provider === "AZURE" ? "Public blob container exposure" : "Public cloud storage exposure",
            "High",
            "Storage",
            "Disable anonymous access and restrict storage permissions to approved identities.",
            "Publicly reachable storage is one of the most common cloud breach causes and should be remediated immediately.",
            ["CIS", "NIST AC-3"]
        );
    }

    if (config.block_public_access === false) {
        addIssue(
            "Public access block disabled",
            "High",
            "Storage",
            "Enable account-level public access blocking for storage resources.",
            "This preventive control reduces accidental exposure caused by later bucket or container policy changes.",
            ["CIS", "AWS Foundational Security"]
        );
    }

    if (config.encryption === false) {
        addIssue(
            "Encryption at rest disabled",
            "High",
            "Data Protection",
            "Enable encryption for volumes, databases, storage buckets, and backups.",
            "Persistent cloud data should always be protected with provider-managed or customer-managed keys.",
            ["NIST SC-28", "PCI DSS"]
        );
    }

    if (config.kms_rotation_enabled === false) {
        addIssue(
            "KMS key rotation disabled",
            "Medium",
            "Data Protection",
            "Enable automatic key rotation for managed encryption keys.",
            "Key rotation reduces long-term impact if key material is exposed or mishandled.",
            ["NIST SC-12", "ISO 27001"]
        );
    }

    if (typeof config.role === "string" && ["admin", "owner", "root", "superadmin"].includes(config.role.toLowerCase())) {
        addIssue(
            "Privileged identity role assigned",
            "High",
            "Identity",
            "Replace broad administrative access with least-privilege role assignments.",
            "High-privilege accounts should be minimized and regularly reviewed.",
            ["NIST AC-6", "ISO 27001"]
        );
    }

    if (config.mfa_enabled === false) {
        addIssue(
            "Multi-factor authentication disabled",
            "High",
            "Identity",
            "Require MFA for all privileged users and administrative access.",
            "MFA sharply reduces account takeover risk from leaked or weak credentials.",
            ["CIS", "NIST IA-2"]
        );
    }

    if (config.root_user_active === true) {
        addIssue(
            "Root or break-glass user remains active",
            "Critical",
            "Identity",
            "Disable regular use of root-level users and monitor emergency account activity.",
            "Always keep root-style accounts locked down because they bypass normal administrative boundaries.",
            ["AWS Foundational Security", "CIS"]
        );
    }

    if (config.password_policy && Number(config.password_policy.min_length) < 12) {
        addIssue(
            "Weak password policy",
            "Medium",
            "Identity",
            "Increase minimum password length and combine it with MFA and rotation policies.",
            "Short passwords are still a common source of compromise in hybrid identity setups.",
            ["CIS", "NIST IA-5"]
        );
    }

    if (config.password_policy && config.password_policy.require_symbols === false) {
        addIssue(
            "Password complexity policy is weak",
            "Low",
            "Identity",
            "Require stronger password complexity or move to passwordless and MFA-based access.",
            "Complexity is not enough alone, but weak baseline policies still increase risk.",
            ["NIST IA-5"]
        );
    }

    if (config.logging_enabled === false) {
        addIssue(
            "Audit logging disabled",
            "High",
            "Monitoring",
            "Enable cloud activity logs and retain them centrally for investigation.",
            "Without audit logs, incident response and accountability are heavily weakened.",
            ["NIST AU-2", "ISO 27001"]
        );
    }

    if (config.alerting_enabled === false) {
        addIssue(
            "Security alerting disabled",
            "Medium",
            "Monitoring",
            "Enable alerting for suspicious activity, IAM changes, and network exposure events.",
            "Detection coverage should include both control-plane and data-plane anomalies.",
            ["NIST SI-4", "CIS"]
        );
    }

    if (config.flow_logs_enabled === false) {
        addIssue(
            "Network flow logging disabled",
            "Medium",
            "Network",
            "Enable VPC, NSG, or subnet flow logs for network visibility.",
            "Flow logs help validate segmentation and investigate suspicious traffic paths.",
            ["NIST AU-12", "CIS"]
        );
    }

    if (Array.isArray(config.firewall)) {
        config.firewall.forEach(rule => {
            const openToWorld = rule.cidr === "0.0.0.0/0";
            const port = Number(rule.port);

            if (openToWorld && [22, 3389, 3306, 5432, 6379, 27017].includes(port)) {
                addIssue(
                    `Sensitive port ${port} exposed to the internet`,
                    "Critical",
                    "Network",
                    "Restrict inbound access to trusted CIDR ranges or private connectivity.",
                    "Administrative and database ports should never be globally exposed in production.",
                    ["CIS", "NIST SC-7"]
                );
            }

            if (openToWorld && [80, 443].includes(port) && rule.tls === false) {
                addIssue(
                    `Internet-facing web port ${port} lacks secure transport enforcement`,
                    "High",
                    "Network",
                    "Redirect or enforce HTTPS and terminate TLS securely.",
                    "Public services should always enforce encrypted transport.",
                    ["NIST SC-8", "PCI DSS"]
                );
            }
        });
    }

    if (config.security_groups_reused === true) {
        addIssue(
            "Shared security groups create broad network trust",
            "Medium",
            "Network",
            "Split network policies by application tier and ownership boundary.",
            "Over-reused firewall groups increase lateral movement risk.",
            ["Zero Trust", "NIST SC-7"]
        );
    }

    if (config.backup_enabled === false) {
        addIssue(
            "Backups are disabled",
            "High",
            "Resilience",
            "Enable scheduled backups and test restore procedures.",
            "Misconfiguration is not only a confidentiality issue; resilience controls are part of cloud security posture.",
            ["NIST CP-9", "ISO 27001"]
        );
    }

    if (config.secret_rotation_enabled === false) {
        addIssue(
            "Secret rotation disabled",
            "Medium",
            "Secrets",
            "Rotate secrets regularly and move static credentials into a secret manager.",
            "Hardcoded or long-lived secrets are a common attack path in cloud environments.",
            ["NIST IA-5", "CIS"]
        );
    }

    if (config.container_public_registry === true) {
        addIssue(
            "Container images pulled from public registry without control",
            "Medium",
            "Containers",
            "Use approved registries, image signing, and vulnerability scanning before deployment.",
            "Container supply-chain controls are important in cloud-native environments.",
            ["NIST SA-12", "MITRE ATT&CK"]
        );
    }

    if (config.container_runtime_privileged === true) {
        addIssue(
            "Privileged container runtime enabled",
            "Critical",
            "Containers",
            "Disable privileged mode and restrict container capabilities.",
            "Privileged containers can break workload isolation and escalate host-level risk.",
            ["CIS Kubernetes", "NIST CM-7"]
        );
    }

    if (config.compliance_mode === false) {
        addIssue(
            "Compliance enforcement mode disabled",
            "Medium",
            "Governance",
            "Enable policy enforcement and automatic compliance evaluation where supported.",
            "Security posture management is stronger when misconfigurations are continuously checked against policy.",
            ["ISO 27001", "CIS"]
        );
    }

    if (provider === "AWS") {
        if (config.versioning_enabled === false) {
            addIssue(
                "S3 bucket versioning disabled",
                "Medium",
                "Storage",
                "Enable versioning to improve recovery against deletion or overwrite events.",
                "Versioning supports both resilience and forensic recovery.",
                ["AWS Well-Architected", "CIS"]
            );
        }

        if (config.cloudtrail_enabled === false) {
            addIssue(
                "CloudTrail disabled",
                "High",
                "Monitoring",
                "Enable CloudTrail across all regions and protect its log destination.",
                "CloudTrail is foundational for AWS audit visibility.",
                ["AWS Foundational Security", "NIST AU-12"]
            );
        }

        if (config.imdsv2_required === false) {
            addIssue(
                "IMDSv2 not enforced for EC2 instances",
                "High",
                "Compute",
                "Require IMDSv2 on instances to reduce metadata service abuse.",
                "Metadata service hardening is a practical defense against credential theft.",
                ["AWS Security Best Practices", "CIS"]
            );
        }

        if (config.rds_public_access === true) {
            addIssue(
                "RDS instance publicly accessible",
                "Critical",
                "Database",
                "Move the database into private subnets and restrict access through application tiers.",
                "Managed databases should rarely be reachable directly from the internet.",
                ["CIS", "NIST SC-7"]
            );
        }
    }

    if (provider === "AZURE") {
        if (config.defender_enabled === false) {
            addIssue(
                "Microsoft Defender for Cloud disabled",
                "High",
                "Monitoring",
                "Enable Defender for Cloud recommendations and threat protection.",
                "Defender improves Azure-native visibility into posture and threats.",
                ["Azure Security Benchmark", "CIS"]
            );
        }

        if (config.key_vault_public_access === true) {
            addIssue(
                "Azure Key Vault allows public network access",
                "High",
                "Secrets",
                "Restrict Key Vault access using private endpoints and approved networks.",
                "Secrets stores should be isolated behind private access controls.",
                ["Azure Security Benchmark", "NIST SC-7"]
            );
        }

        if (config.storage_secure_transfer_required === false) {
            addIssue(
                "Azure Storage secure transfer not required",
                "High",
                "Storage",
                "Enable secure transfer required for all Azure Storage accounts.",
                "This prevents unencrypted access to storage endpoints.",
                ["Azure Security Benchmark", "PCI DSS"]
            );
        }

        if (config.nsg_default_allow === true) {
            addIssue(
                "NSG contains permissive default allow behavior",
                "Critical",
                "Network",
                "Tighten NSG rules and remove broad inbound allow entries.",
                "Overly permissive NSGs are a common Azure exposure point.",
                ["CIS", "NIST SC-7"]
            );
        }
    }

    if (provider === "GCP") {
        if (config.audit_config === false) {
            addIssue(
                "Cloud Audit Logs disabled",
                "High",
                "Monitoring",
                "Enable administrative, data access, and policy-denied audit logging.",
                "Audit visibility is essential for secure GCP operations.",
                ["Google Cloud Security Foundations", "NIST AU-12"]
            );
        }

        if (config.os_login_required === false) {
            addIssue(
                "OS Login not enforced for compute instances",
                "Medium",
                "Compute",
                "Enable OS Login for centralized SSH access governance.",
                "Centralized instance access improves traceability and access control.",
                ["Google Cloud Security Foundations", "CIS"]
            );
        }

        if (config.service_account_key_exposed === true) {
            addIssue(
                "Long-lived service account key detected",
                "Critical",
                "Identity",
                "Remove exposed keys and prefer short-lived workload identity mechanisms.",
                "Service account keys are highly sensitive and commonly abused.",
                ["NIST IA-5", "Google Cloud Best Practices"]
            );
        }

        if (config.sql_public_ip === true) {
            addIssue(
                "Cloud SQL instance uses a public IP",
                "High",
                "Database",
                "Use private IP connectivity and restrict external access.",
                "Databases should be kept off the public internet whenever possible.",
                ["CIS", "NIST SC-7"]
            );
        }
    }

    if (issues.length === 0) {
        addIssue(
            "No major misconfigurations detected",
            "Safe",
            "Posture",
            "No immediate action required.",
            "The uploaded configuration appears healthy against the current rule set. Continue periodic reassessment.",
            ["Best Practice"]
        );
    }

    return issues;
}

function calculateRiskScore(issues) {
    const weights = {
        Critical: 28,
        High: 18,
        Medium: 10,
        Low: 4,
        Safe: 0
    };

    return Math.min(100, issues.reduce((sum, item) => sum + (weights[item.severity] || 0), 0));
}

function summarizeFindings(issues) {
    return issues.reduce((acc, issue) => {
        acc[issue.severity] = (acc[issue.severity] || 0) + 1;
        return acc;
    }, { Critical: 0, High: 0, Medium: 0, Low: 0, Safe: 0 });
}

module.exports = {
    scanConfiguration,
    calculateRiskScore,
    summarizeFindings
};
