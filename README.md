# 🔐 GCP IAM Over-Privileged Account Detection

This tool identifies users and service accounts with **overly permissive IAM roles** across Google Cloud Platform projects. It detects risky roles like `roles/owner`, `roles/editor`, and `roles/viewer` that violate the principle of least privilege, then generates an actionable audit report.

Supports scanning a **single GCP project** or an **entire GCP organization**.

---

## 📌 Why This Project Matters

IAM misconfigurations are one of the top causes of security breaches in cloud environments. This tool empowers security engineers, cloud architects, and auditors to:

- Detect **excessive permissions** before they lead to incidents
- Promote the use of **custom roles** or more restrictive predefined roles
- Export results for compliance reporting or continuous monitoring
- Integrate into automated audit workflows

---

## 🚀 Features

- ✅ Detect over-permissioned principals in a project or organization
- ✅ Supports GCP Organization-wide scanning using `--org`
- ✅ Outputs CSV report with project ID, role, and remediation guidance
- ✅ Timestamped findings for historical trend analysis
- 🔜 (Future) Export to BigQuery or send results to Looker Studio
- 🔜 (Future) Slack/email notifications and auto-remediation

---

## 🔧 Technologies Used

| Component             | Purpose                                     |
|----------------------|---------------------------------------------|
| Python (3.8+)         | Core script and CSV processing               |
| `gcloud` CLI         | Fetch IAM policies and project list         |
| Cloud Asset API      | IAM asset retrieval (indirect via gcloud)   |
| CSV                  | Report output format                        |

---

## 📦 Prerequisites

- ✅ Google Cloud CLI (`gcloud`) installed and authenticated
- ✅ IAM role: `Viewer` + `Security Reviewer` at the project or org level
- ✅ Cloud Asset Inventory API enabled

```bash
gcloud services enable cloudasset.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com
