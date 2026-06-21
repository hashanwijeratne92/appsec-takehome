#!/usr/bin/env python3

import subprocess
import json
import sys
from pathlib import Path

repo_path = str(Path(__file__).resolve().parent.parent)
raw_report = Path(repo_path) / "artifacts" / "secrets.raw.json"
filltered_report = Path(repo_path) / "artifacts" / "secrets.filtered.json"
baseline_file = Path(repo_path) / "baseline.json"

def load_json(file_path, default):
    if file_path.exists():
        with open(file_path, "r") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    else:
        return default
    
def finding_key(finding):
    return {
        "RuleID": finding.get("RuleID"),
        "File": finding.get("File"),
        "Secret": finding.get("Secret"),
    }

def gitleaks():

    command = ["docker",
               "run",
               "--rm",
               "-v", f"{repo_path}:/appsec-takehome",
               "zricethezav/gitleaks:latest",
               "dir",
               "/appsec-takehome/testdata",
               "--config", "/appsec-takehome/config/gitleaks.toml",
               "--report-format", "json",
               "--report-path", "/appsec-takehome/artifacts/secrets.raw.json"]
    
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode not in [0, 1]:  # Gitleaks returns 1 if secrets are found
        print("Error running gitleaks:")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        sys.exit(result.returncode)
    

def main():
    gitleaks()

    raw_report_data = load_json(raw_report, [])
    baseline_data = load_json(baseline_file, [])
    filltered_data = []

    baseline_keys = {
        (
            item["RuleID"], 
            item["File"], 
            item["Secret"]
        )         
        for item in baseline_data
    }

    for finding in raw_report_data:
        key = finding_key(finding)

        key_tuple = (key["RuleID"], key["File"], key["Secret"])

        if key_tuple not in baseline_keys:
            filltered_data.append(finding)

    with open(filltered_report, "w") as f:
        json.dump(filltered_data, f, indent=4)

    if filltered_data:
        print(f"Taks 1: New secrets found: {len(filltered_data)}")
        print(f"Exit code: 1")
        sys.exit(1)
    else:
        print("Taks 1: No new secrets found.")
        print(f"Exit code: 0")
        sys.exit(0)

if __name__ == "__main__":
    main()

