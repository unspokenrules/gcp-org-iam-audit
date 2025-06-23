import argparse
import json
import subprocess
import csv

def get_all_projects(org_id):
    cmd = [
        "gcloud", "projects", "list",
        f"--filter=parent.type=organization AND parent.id={org_id}",
        "--format=json"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    projects = json.loads(result.stdout)
    return [p["projectId"] for p in projects]

def get_iam_policy(project_id):
    cmd = ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

def is_overprivileged(role):
    return role in ["roles/editor", "roles/owner", "roles/iam.serviceAccountUser"]

def audit_project(project_id):
    try:
        policy = get_iam_policy(project_id)
    except subprocess.CalledProcessError:
        print(f"⚠️ Skipping {project_id}: unable to fetch IAM policy.")
        return []

    results = []
    for binding in policy.get("bindings", []):
        role = binding["role"]
        if is_overprivileged(role):
            for member in binding["members"]:
                results.append({
                    "project_id": project_id,
                    "principal": member,
                    "role": role,
                    "recommendation": "Use a custom role or least privilege alternative"
                })
    return results

def save_report(data, filename="org_iam_audit_report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project_id", "principal", "role", "recommendation"])
        writer.writeheader()
        writer.writerows(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True, help="GCP organization ID")
    args = parser.parse_args()

    all_projects = get_all_projects(args.org)
    print(f"Found {len(all_projects)} projects under org {args.org}")

    all_audit_data = []
    for pid in all_projects:
        print(f"Auditing project: {pid}")
        audit_data = audit_project(pid)
        all_audit_data.extend(audit_data)

    save_report(all_audit_data)
    print(f"✅ Audit complete. Report saved to org_iam_audit_report.csv")
