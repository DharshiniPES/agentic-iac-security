# Evaluation

## Test Cases

| Rule | Terraform Test Case | Expected | Result |
|------|---------------------|----------|--------|
| RULE_001 | Public S3 Bucket | Detected | PASS |
| RULE_002 | Open Security Group | Detected | PASS |
| RULE_003 | Public SSH | Detected | PASS |
| RULE_004 | IAM Wildcard Policy | Detected | PASS |
| RULE_005 | Missing S3 Encryption | Detected | PASS |
| RULE_006 | Missing S3 Versioning | Detected | PASS |
| RULE_007 | Unencrypted EBS | Detected | PASS |
| RULE_008 | Missing CloudTrail | Detected | PASS |

---

## Summary

Total Rules Tested: 8

Successful Detections: 8

Detection Accuracy: 100%

False Positives: 0

False Negatives: 0