import argparse
import json
import subprocess
import csv
from datetime import datetime

def get_all_projects(org_id):
    print(f"Fetching all projects under org {org_id}...")
    cmd = [
        "gcloud", "projects", "list",
        f"--filter=parent.id={org_id}",
        "--format=value(projectId)"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    project_ids = result.stdout.strip().splitlines()
    print(f"Found {len(project_ids)} projects.")
    return project_ids

def get_iam_policy(project_id):
    cmd = ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

def is_overprivileged(role):
    return role in ["roles/editor", "roles/owner", "roles/viewer"]

def audit_project(project_id):
    policy = get_iam_policy(project_id)
    results = []
    timestamp = datetime.utcnow().isoformat() + "Z"

    for binding in policy.get("bindings", []):
        role = binding["role"]
        if is_overprivileged(role):
            for member in binding["members"]:
                results.append({
                    "timestamp": timestamp,
                    "project_id": project_id,
                    "principal": member,
                    "role": role,
                    "recommendation": "Use a custom role or least privilege alternative"
                })
    return results

def save_report(data, filename="gcp_org_iam_audit_report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "project_id", "principal", "role", "recommendation"])
        writer.writeheader()
        writer.writerows(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", help="GCP project ID (optional)")
    parser.add_argument("--org", help="GCP organization ID (to scan all projects)")
    args = parser.parse_args()

    all_results = []

    if args.org:
        project_ids = get_all_projects(args.org)
        for pid in project_ids:
            print(f"Auditing project: {pid}")
            results = audit_project(pid)
            all_results.extend(results)
    elif args.project:
        results = audit_project(args.project)
        all_results = results
    else:
        parser.error("You must provide either --project or --org")

    save_report(all_results)
    print("Audit complete. Report saved to gcp_org_iam_audit_report.csv")
