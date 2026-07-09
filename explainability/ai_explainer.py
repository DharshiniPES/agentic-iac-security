class ExplainabilityEngine:

    def generate_explanations(self, findings):

        explained_findings = []

        for finding in findings:

            if finding["rule_id"] == "RULE_001":

                finding["explanation"] = (
                    "This S3 bucket allows public access. "
                    "Attackers may discover and access sensitive files. "
                    "This can lead to data exposure and compliance violations."
                )

            elif finding["rule_id"] == "RULE_002":

                finding["explanation"] = (
                    "This Security Group allows inbound traffic from any IP address "
                    "(0.0.0.0/0). Publicly accessible services increase the attack "
                    "surface and may be targeted by attackers through scanning, "
                    "brute-force attempts, or exploitation of vulnerabilities."
                )
            elif finding["rule_id"] == "RULE_003":

                finding["explanation"] = (
                    "This Security Group exposes SSH (port 22) "
                    "to the entire Internet. Public SSH services "
                    "are frequently targeted by attackers using "
                    "brute-force attacks, credential stuffing, "
                    "and vulnerability scanning."
                )

            explained_findings.append(finding)

        return explained_findings