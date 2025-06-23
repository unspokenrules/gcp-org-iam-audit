import argparse
import json
import subprocess
import csv
from datetime import datetime

def run_gcloud(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

def get_all_folders(org_id):
    cmd = [
        "gcloud", "resource-manager", "folders", "list",
        f"--organization={org_id}",
        "--format=json"
    ]
    folders = run_gcloud(cmd)
    all_folders = {f["name"]: f for f in folders}

    queue = [f["name"] for f in folders]
    while queue:
        folder_id = queue.pop(0)
        cmd = [
            "gcloud", "resource-manager", "folders", "list",
            f"--folder={folder_id}",
            "--format=json"
        ]
        children = run_gcloud(cmd)
        for child in children:
            all_folders[child["name"]] = child
            queue.append(child["name"])
    return list(all_folders.keys())

def get_projects_from_parent(parent_type, parent_id):
    parent_flag = f"--{parent_type}={parent_id}"
    cmd = ["gcloud", "projects", "list", parent_flag, "--format=json"]
    try:
        return run_gcloud(cmd)
    except subprocess.CalledProcessError:
        return []

def get_all_projects(org_id):
    print("🔍 Fetching all projects under org, including nested folders...")
    projects = []

    projects += get_projects_from_parent("organization", org_id)
    folders = get_all_folders(org_id)
    print(f"📁 Found {len(folders)} folders")

    for folder_name in folders:
        folder_id = folder_name.split("/")[-1]
        folder_projects = get_projects_from_parent("folder", folder_id)
        projects += folder_projects

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

def save_report(data):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"gcp_org_wide_project_iam_audit_{timestamp}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["project_id", "principal", "role", "recommendation"])
        writer.writeheader()
        writer.writerows(data)
    print(f"📁 Report saved to: {filename}")

def print_summary(results):
    total_findings = len(results)
    role_count = {}

    for entry in results:
        role = entry["role"]
        role_count[role] = role_count.get(role, 0) + 1

    print("\n📊 Summary:")
    print(f"   Total overprivileged entries: {total_findings}")
    for role, count in role_count.items():
        print(f"   {role}: {count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True, help="GCP organization ID")
    args = parser.parse_args()

    all_projects = get_all_projects(args.org)
    print(f"✅ Found {len(all_projects)} total projects")

    all_audit_data = []
    for pid in all_projects:
        print(f"🔎 Auditing project: {pid}")
        audit_data = audit_project(pid)
        all_audit_data.extend(audit_data)

    save_report(all_audit_data)
    print_summary(all_audit_data)
    print("✅ IAM audit completed.")
