#!/usr/bin/env python3

import json
import subprocess
from collections import Counter
from pathlib import Path

repo_path = str(Path(__file__).resolve().parent.parent)
raw_report = Path(repo_path) / "artifacts" / "secrets.raw.json"
filtered_report = Path(repo_path) / "artifacts" / "secrets.filtered.json"
triage_report = Path(repo_path) / "artifacts" / "triage.md"

serverity_rank = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4
}

rule_severity = {
    "demo-azure-access-key": "Critical",
    "demo-aws-access-key": "High",
    "demo-github-token": "High",
    "demo-db-password": "Medium",
    "demo-admin-password": "Medium",
    "demo-client-password": "Low"
}

def load_json(file_path, default):
    if file_path.exists():
        with open(file_path, "r") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    else:
        return default
    
def get_rule_id(finding: dict) -> str:
    return finding.get("RuleID", "unknown")


def get_severity(finding: dict) -> str:
    rule_id = get_rule_id(finding)
    return rule_severity.get(rule_id, "MEDIUM")


def get_category(finding: dict) -> str:
    return get_rule_id(finding)


    
def create_report(raw_findings, filtered_findings):

    severity_counts = Counter(get_severity(f) for f in filtered_findings)
    category_counts = Counter(get_category(f) for f in filtered_findings)
    suppressed_count = max(len(raw_findings) - len(filtered_findings), 0)

    lines = []
    lines.append("# Triage Report\n\n")
    lines.append("This report summarizes the findings from the latest secret scan.\n\n")
    lines.append("## Summary\n\n")
    lines.append(f"- Total raw findings: {len(raw_findings)}")
    lines.append(f"- Suppressed findings: {suppressed_count}")
    lines.append(f"- New findings: {len(filtered_findings)}")       

    if not filtered_findings:
        lines.append("No new findings to triage.\n")
        return "\n".join(lines)
    
    lines.append("\n\n## Count by Serverity\n")
    lines.append(f"| {'Severity':<10} | {'Count':<5} |")
    lines.append(f"| {'-'*10} | {'-'*5} |")

    for severity in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {severity:<10} | {severity_counts.get(severity, 0):<5} |")

    lines.append("\n\n## Count by Category\n")
    lines.append(f"| {'Category':<25} | {'Count':<5} |")
    lines.append(f"| {'-'*25} | {'-'*5} |")
                  

    for category in sorted(category_counts):
        lines.append(f"| {category:<25} | {category_counts[category]:<5} |")

    if not category_counts:
        lines.append("| None | 0 |")

    sorted_findings = sorted(
        filtered_findings,
        key=lambda f: (
            serverity_rank.get(rule_severity.get(f.get("RuleID"), "Low"), 5),
            f.get("File", ""),
            f.get("Secret", "")
        )
    )

    lines.append(f"\n\n")
    lines.append(f"| {'Severity':<10} | {'Secret':<25} | {'File':<30} | {'Rule':<30} |")
    lines.append(f"| {'-'*10} | {'-'*25} | {'-'*30} | {'-'*30} |")

    for finding in sorted_findings[:5]:
        rule_id = finding.get("RuleID")
        severity = rule_severity.get(rule_id, "Low")
        file_path = finding.get("File", "").replace("/appsec-takehome/", "")
        secret = finding.get("Secret", "")
        lines.append(f"| {severity:<10} | {secret:<25} | {file_path:<30} | {rule_id:<30} |")

    return "\n".join(lines)


def main():
    raw_report_data = load_json(raw_report, [])
    filtered_report_data = load_json(filtered_report, [])

    report = create_report(raw_report_data, filtered_report_data)
    triage_report.write_text(report, encoding="utf-8")

    print(f"Taks 3 - Triage report generated at: {triage_report}")
     

if __name__ == "__main__":
    main()


