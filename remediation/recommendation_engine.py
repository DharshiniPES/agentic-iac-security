class RecommendationEngine:

    def generate_recommendations(self, findings):

        recommended_findings = []

        for finding in findings:

            if finding["rule_id"] == "RULE_001":

                finding["recommendation"] = (
                    "Enable all S3 Public Access Block "
                    "settings to prevent public exposure "
                    "of bucket contents."
                )

            elif finding["rule_id"] == "RULE_002":

                finding["recommendation"] = (
                    "Restrict inbound access to trusted IP "
                    "ranges instead of using 0.0.0.0/0. "
                    "Expose only the required ports and "
                    "follow the Principle of Least Privilege."
                )
            elif finding["rule_id"] == "RULE_003":

                finding["recommendation"] = (
                    "Restrict SSH access to trusted IP "
                    "addresses only. Avoid exposing port "
                    "22 to the public Internet. Consider "
                    "using a VPN or bastion host for "
                    "administrative access."
                )
            elif finding["rule_id"] == "RULE_004":

                finding["recommendation"] = (
                    "Replace wildcard permissions with only the "
                    "specific actions required. Follow the Principle "
                    "of Least Privilege when designing IAM policies."
                )
            elif finding["rule_id"] == "RULE_005":

                finding["recommendation"] = (
                    "Enable Server-Side Encryption (SSE-S3 or "
                    "SSE-KMS) for this S3 bucket to protect "
                    "stored data at rest."
                )
            elif finding["rule_id"] == "RULE_006":

                finding["recommendation"] = (
                    "Enable S3 Versioning to maintain multiple versions "
                    "of objects and improve protection against accidental "
                    "deletion or modification."
                )
            elif finding["rule_id"] == "RULE_007":

                finding["recommendation"] = (
                    "Enable EBS encryption to protect data "
                    "stored on the volume. Consider using "
                    "AWS KMS for managing encryption keys."
                )
            elif finding["rule_id"] == "RULE_008":

                finding["recommendation"] = (
                    "Enable AWS CloudTrail to record API "
                    "activity across your AWS environment. "
                    "Store logs securely and monitor them "
                    "regularly."
                )

            recommended_findings.append(
                finding
            )

        return recommended_findings