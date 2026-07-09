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
            elif finding["rule_id"] == "RULE_004":

                finding["explanation"] = (
                    "This IAM policy grants wildcard permissions "
                    "using Action (*). Excessive permissions violate "
                    "the Principle of Least Privilege and may allow "
                    "attackers to perform unauthorized actions if "
                    "the credentials are compromised."
                )
            elif finding["rule_id"] == "RULE_005":

                finding["explanation"] = (
                    "This S3 bucket does not have server-side "
                    "encryption enabled. Data stored in the bucket "
                    "may be exposed if unauthorized access to the "
                    "underlying storage occurs."
                )
            elif finding["rule_id"] == "RULE_006":

                finding["explanation"] = (
                    "This S3 bucket does not have versioning enabled. "
                    "Without versioning, deleted or overwritten objects "
                    "cannot be easily recovered, increasing the risk of "
                    "accidental data loss."
                )
            elif finding["rule_id"] == "RULE_007":

                finding["explanation"] = (
                    "This EBS volume is not encrypted. "
                    "If unauthorized access to the storage "
                    "or snapshots occurs, sensitive data "
                    "could be exposed."
                )
            elif finding["rule_id"] == "RULE_008":

                finding["explanation"] = (
                    "AWS CloudTrail is not enabled. Without "
                    "CloudTrail, security events and API "
                    "activities are not recorded, making "
                    "incident investigation and compliance "
                    "more difficult."
                )
            explained_findings.append(finding)

        return explained_findings