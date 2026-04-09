# Web-Based Automated Cloud Security and Misconfiguration Detection System

## Overview
This project is now a small full-stack Node.js application for cloud security posture assessment in multi-cloud environments. It includes:
- an administrator login page
- a backend API for authentication, scanning, and history
- an admin dashboard for analysis and reporting
- a richer multi-cloud rule engine for AWS, Azure, and GCP

## Architecture
### Frontend
- `public/index.html`: login page
- `public/dashboard.html`: admin dashboard
- `public/auth.js`: authentication flow
- `public/dashboard.js`: scan, reporting, chart, export, and history workflow
- `public/styles.css`: UI styling

### Backend
- `server.js`: Node.js HTTP server and API routes
- `scanner.js`: security rule engine and risk scoring
- `db.js`: SQLite database layer for users and scan history
- `data/scan-history.json`: legacy JSON history used only for migration

## Main Features
- Demo login for admin access
- SQLite-backed users and scan history
- Backend-driven scan API
- Dashboard with risk score and chart
- Detailed findings table with filter and search
- PDF export and JSON export
- Server-side scan history
- Remediation roadmap
- Provider-specific rules for AWS, Azure, and GCP

## Demo Login
- Username: `admin`
- Password: `admin123`

## Rule Coverage
### Common Controls
- Public storage exposure
- Public access block disabled
- Encryption disabled
- KMS key rotation disabled
- Privileged role assignment
- MFA disabled
- Root user active
- Weak password policy
- Weak password complexity
- Audit logging disabled
- Security alerting disabled
- Network flow logs disabled
- Open admin and database ports
- Missing secure transport on internet-facing services
- Shared security group overuse
- Backups disabled
- Secret rotation disabled
- Public container registry usage
- Privileged container runtime
- Compliance mode disabled

### AWS Controls
- S3 versioning disabled
- CloudTrail disabled
- IMDSv2 not enforced
- RDS publicly accessible

### Azure Controls
- Defender for Cloud disabled
- Key Vault public access enabled
- Storage secure transfer disabled
- NSG overly permissive

### GCP Controls
- Cloud Audit Logs disabled
- OS Login not enforced
- Service account key exposure
- Cloud SQL public IP enabled

## How To Run
1. Open PowerShell in `C:\Users\hp\OneDrive\Desktop\Cloud`
2. Run:

```powershell
node server.js
```

3. Open:
[http://localhost:3000](http://localhost:3000)

You can also use:

```powershell
npm start
```

## Database
- Engine: SQLite via `better-sqlite3`
- Database file: `C:\Users\hp\AppData\Local\CloudSecurityScanner\cloud-security.db`
- Seeded admin user is created automatically on first run
- Existing JSON history is migrated into SQLite automatically if present
- Optional cloud override: set `CLOUD_SECURITY_DATA_DIR` to a persistent mounted folder

## Cloud Deployment
### Deployment-ready files
- `Dockerfile`
- `.dockerignore`

### Recommended approach
Use a cloud platform that supports a persistent disk or mounted volume because this project stores users and scan history in SQLite.

### Required environment
- `PORT`: provided by most cloud platforms automatically
- `CLOUD_SECURITY_DATA_DIR`: set this to your mounted persistent storage path

### Example persistent path
- Railway volume mount: `/app/data`
- Render persistent disk mount: `/app/data`

### Deployment checklist
1. Push the project to GitHub
2. Create a new web service on your cloud platform
3. Deploy using the `Dockerfile`
4. Attach a persistent volume or disk
5. Set `CLOUD_SECURITY_DATA_DIR=/app/data`
6. Expose the service port provided by the platform
7. Open `/api/health` to confirm the backend is running
8. Open the main app URL and register or log in

## API Endpoints
- `POST /api/login`
- `POST /api/logout`
- `GET /api/session`
- `POST /api/scan`
- `GET /api/history`
- `GET /api/health`

## Sample Files
Use the files in [samples](C:\Users\hp\OneDrive\Desktop\Cloud\samples):
- `aws-critical.yaml`
- `aws-safe.yaml`
- `azure-medium.json`
- `gcp-critical.json`
- `gcp-safe.yaml`
- `invalid-test.json`

## Suggested Demo Flow
1. Start the Node.js server
2. Login with the admin account
3. Scan `aws-critical.yaml` and show the high-risk output
4. Apply search and severity filtering
5. Show scan history stored by the backend
6. Export the PDF and JSON reports
7. Scan a safer sample and compare the lower score

## Viva Talking Points
- The system solves cloud misconfiguration detection across multiple providers.
- It separates authentication, dashboard UI, API routes, persistence, and scan logic into modules.
- It demonstrates full-stack development using a Node.js backend and browser frontend.
- It covers practical cloud security domains including storage, identity, network, monitoring, secrets, resilience, and containers.

## Future Scope
- Real AWS, Azure, and GCP SDK integration
- Database-backed authentication
- Role-based access control
- Scheduled scans and email alerts
- Auto-remediation workflows
- AI-generated compliance summaries
