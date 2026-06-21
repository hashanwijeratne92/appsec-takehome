# Triage Report


This report summarizes the findings from the latest secret scan.


## Summary


- Total raw findings: 8
- Suppressed findings: 1
- New findings: 7


## Count by Serverity

| Severity   | Count |
| ---------- | ----- |
| Critical   | 1     |
| High       | 3     |
| Medium     | 2     |
| Low        | 1     |


## Count by Category

| Category                  | Count |
| ------------------------- | ----- |
| demo-admin-password       | 1     |
| demo-aws-access-key       | 2     |
| demo-azure-access-key     | 1     |
| demo-client-password      | 1     |
| demo-db-password          | 1     |
| demo-github-token         | 1     |



| Severity   | Secret                    | File                           | Rule                           |
| ---------- | ------------------------- | ------------------------------ | ------------------------------ |
| Critical   | AZABCDEFGHJKLMNPQ2        | testdata/new-secrets.env       | demo-azure-access-key          |
| High       | AKIAABCDEFGHJKLMNPQ2      | testdata/dev-secrets.env       | demo-aws-access-key            |
| High       | AKIAABCDEFGHJKLMNPQ2      | testdata/new-secrets.env       | demo-aws-access-key            |
| High       | gitABCDEFGHJKLMNPQ2       | testdata/new-secrets.env       | demo-github-token              |
| Medium     | abc123                    | testdata/new-secrets.env       | demo-db-password               |
