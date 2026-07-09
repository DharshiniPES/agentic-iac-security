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

            recommended_findings.append(
                finding
            )

        return recommended_findings