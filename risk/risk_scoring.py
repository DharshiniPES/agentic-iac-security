class RiskScoringEngine:

    def calculate_risk(self, findings):

        scored_findings = []

        severity_scores = {
            "LOW": 25,
            "MEDIUM": 50,
            "HIGH": 75,
            "CRITICAL": 100
        }

        for finding in findings:

            score = severity_scores.get(
                finding["severity"],
                0
            )

            finding["risk_score"] = score

            scored_findings.append(finding)

        return scored_findings