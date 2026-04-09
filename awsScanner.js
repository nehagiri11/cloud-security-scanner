"use strict";

const { STSClient, GetCallerIdentityCommand } = require("@aws-sdk/client-sts");
const { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand, GetBucketEncryptionCommand, GetBucketVersioningCommand } = require("@aws-sdk/client-s3");
const { EC2Client, DescribeSecurityGroupsCommand } = require("@aws-sdk/client-ec2");
const { IAMClient, GetAccountSummaryCommand } = require("@aws-sdk/client-iam");
const { RDSClient, DescribeDBInstancesCommand } = require("@aws-sdk/client-rds");
const { CloudTrailClient, DescribeTrailsCommand } = require("@aws-sdk/client-cloudtrail");

async function scanAwsAccount(options) {
    const region = options.region || "ap-south-1";
    const clientConfig = buildClientConfig(options, region);

    const stsClient = new STSClient(clientConfig);
    const identity = await stsClient.send(new GetCallerIdentityCommand({}));

    const findings = [];

    await Promise.all([
        scanS3(clientConfig, findings),
        scanSecurityGroups(clientConfig, findings),
        scanIam(clientConfig, findings),
        scanRds(clientConfig, findings),
        scanCloudTrail(clientConfig, findings)
    ]);

    if (!findings.length) {
        findings.push(makeFinding(
            "No major AWS misconfigurations detected",
            "Safe",
            "Posture",
            "No immediate remediation required.",
            "The connected AWS account passed the current live rule set. Continue periodic posture assessments.",
            ["AWS Best Practice"]
        ));
    }

    return {
        accountId: identity.Account || "Unknown",
        arn: identity.Arn || "Unknown",
        userId: identity.UserId || "Unknown",
        region,
        findings
    };
}

function buildClientConfig(options, region) {
    const accessKeyId = options.accessKeyId || process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = options.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
    const sessionToken = options.sessionToken || process.env.AWS_SESSION_TOKEN;

    const config = { region };

    if (accessKeyId && secretAccessKey) {
        config.credentials = {
            accessKeyId,
            secretAccessKey,
            sessionToken
        };
    }

    return config;
}

async function scanS3(clientConfig, findings) {
    try {
        const s3 = new S3Client(clientConfig);
        const bucketResponse = await s3.send(new ListBucketsCommand({}));
        const buckets = bucketResponse.Buckets || [];

        await Promise.all(
            buckets.slice(0, 20).map(async bucket => {
                const bucketName = bucket.Name;

                try {
                    await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
                } catch (error) {
                    if (isAwsNotFound(error)) {
                        findings.push(makeFinding(
                            `S3 bucket ${bucketName} is missing Public Access Block`,
                            "High",
                            "Storage",
                            "Enable Public Access Block for the bucket and restrict bucket policies.",
                            "Buckets without Public Access Block are more likely to be exposed accidentally through future policy changes.",
                            ["CIS", "AWS Foundational Security"]
                        ));
                    }
                }

                try {
                    await s3.send(new GetBucketEncryptionCommand({ Bucket: bucketName }));
                } catch (error) {
                    if (isAwsNotFound(error)) {
                        findings.push(makeFinding(
                            `S3 bucket ${bucketName} has encryption disabled`,
                            "High",
                            "Storage",
                            "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                            "Default encryption helps protect object data at rest and is expected in secure AWS baselines.",
                            ["CIS", "NIST SC-28"]
                        ));
                    }
                }

                try {
                    const versioning = await s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
                    if (versioning.Status !== "Enabled") {
                        findings.push(makeFinding(
                            `S3 bucket ${bucketName} has versioning disabled`,
                            "Medium",
                            "Storage",
                            "Enable S3 versioning to support recovery from accidental deletion or overwrite.",
                            "Versioning improves both resilience and forensic recovery for object storage.",
                            ["AWS Well-Architected", "CIS"]
                        ));
                    }
                } catch {
                    // Ignore versioning read errors for now.
                }
            })
        );
    } catch {
        findings.push(makeFinding(
            "S3 live scan could not inspect storage resources",
            "Low",
            "Storage",
            "Verify the AWS credentials include read access to S3 bucket configuration APIs.",
            "Some AWS APIs may be blocked by limited permissions. The scan continued with other service checks.",
            ["Operational Note"]
        ));
    }
}

async function scanSecurityGroups(clientConfig, findings) {
    try {
        const ec2 = new EC2Client(clientConfig);
        const response = await ec2.send(new DescribeSecurityGroupsCommand({}));
        const groups = response.SecurityGroups || [];

        groups.forEach(group => {
            (group.IpPermissions || []).forEach(permission => {
                const fromPort = Number(permission.FromPort);
                const cidrs = permission.IpRanges || [];
                const openToWorld = cidrs.some(range => range.CidrIp === "0.0.0.0/0");

                if (openToWorld && [22, 3389, 3306, 5432, 6379, 27017].includes(fromPort)) {
                    findings.push(makeFinding(
                        `Security group ${group.GroupName || group.GroupId} exposes sensitive port ${fromPort}`,
                        "Critical",
                        "Network",
                        "Restrict the security group rule to trusted CIDR ranges or private connectivity.",
                        "Administrative and database ports should not be open to the entire internet in AWS environments.",
                        ["CIS", "NIST SC-7"]
                    ));
                }
            });
        });
    } catch {
        findings.push(makeFinding(
            "EC2 security group inspection was limited",
            "Low",
            "Network",
            "Grant read access to EC2 security group metadata for deeper live inspection.",
            "The scan continued, but some network exposure checks may have been skipped due to limited permissions.",
            ["Operational Note"]
        ));
    }
}

async function scanIam(clientConfig, findings) {
    try {
        const iam = new IAMClient(clientConfig);
        const summary = await iam.send(new GetAccountSummaryCommand({}));
        const map = summary.SummaryMap || {};

        if (Number(map.AccountMFAEnabled || 0) !== 1) {
            findings.push(makeFinding(
                "AWS account does not have root MFA enabled",
                "Critical",
                "Identity",
                "Enable MFA on the root account immediately and avoid day-to-day root usage.",
                "Root account MFA is a core AWS baseline control and a common audit requirement.",
                ["CIS", "AWS Foundational Security"]
            ));
        }

        if (Number(map.AccountAccessKeysPresent || 0) > 0) {
            findings.push(makeFinding(
                "Root account access keys are present",
                "High",
                "Identity",
                "Delete root access keys and use least-privilege IAM roles or users instead.",
                "Root keys significantly increase blast radius because they bypass normal IAM boundaries.",
                ["CIS", "NIST AC-6"]
            ));
        }
    } catch {
        findings.push(makeFinding(
            "IAM account summary could not be fully inspected",
            "Low",
            "Identity",
            "Verify the AWS credentials include iam:GetAccountSummary permission.",
            "Identity checks are most valuable when the scanner can review root account and MFA posture.",
            ["Operational Note"]
        ));
    }
}

async function scanRds(clientConfig, findings) {
    try {
        const rds = new RDSClient(clientConfig);
        const response = await rds.send(new DescribeDBInstancesCommand({}));
        const instances = response.DBInstances || [];

        instances.forEach(instance => {
            if (instance.PubliclyAccessible) {
                findings.push(makeFinding(
                    `RDS instance ${instance.DBInstanceIdentifier} is publicly accessible`,
                    "Critical",
                    "Database",
                    "Move the database into private subnets and restrict connectivity through trusted application tiers.",
                    "Publicly reachable managed databases are a high-risk exposure pattern in AWS.",
                    ["CIS", "NIST SC-7"]
                ));
            }
        });
    } catch {
        findings.push(makeFinding(
            "RDS live scan could not inspect database instances",
            "Low",
            "Database",
            "Grant read access to RDS instance metadata to include public accessibility checks.",
            "The scan continued, but database posture may not be fully represented.",
            ["Operational Note"]
        ));
    }
}

async function scanCloudTrail(clientConfig, findings) {
    try {
        const cloudTrail = new CloudTrailClient(clientConfig);
        const response = await cloudTrail.send(new DescribeTrailsCommand({ includeShadowTrails: true }));
        const trails = response.trailList || [];

        if (!trails.length) {
            findings.push(makeFinding(
                "CloudTrail is not configured",
                "High",
                "Monitoring",
                "Enable at least one multi-region CloudTrail and protect its logging destination.",
                "CloudTrail is foundational for AWS audit visibility and incident response.",
                ["AWS Foundational Security", "NIST AU-12"]
            ));
        }
    } catch {
        findings.push(makeFinding(
            "CloudTrail inspection was limited",
            "Low",
            "Monitoring",
            "Grant read access to CloudTrail so live audit logging checks can be completed.",
            "Audit visibility is important for secure operations and investigation readiness.",
            ["Operational Note"]
        ));
    }
}

function makeFinding(issue, severity, category, fix, ai, compliance) {
    return { issue, severity, category, fix, ai, compliance };
}

function isAwsNotFound(error) {
    return ["NoSuchPublicAccessBlockConfiguration", "ServerSideEncryptionConfigurationNotFoundError"].includes(error.name);
}

module.exports = {
    scanAwsAccount
};
