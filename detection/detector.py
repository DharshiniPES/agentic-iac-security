from detection.rule_engine import RuleEngine


class DetectionEngine:

    def __init__(self):

        self.rule_engine = RuleEngine()

    def run_detection(self, resources):

        findings = []

        findings.extend(
            self.rule_engine.check_public_s3(resources)
        )

        findings.extend(
            self.rule_engine.check_open_security_groups(resources)
        )

        findings.extend(
            self.rule_engine.check_open_ssh(resources)
        )

        findings.extend(
            self.rule_engine.check_iam_wildcards(resources)
        )

        findings.extend(
            self.rule_engine.check_missing_s3_encryption(resources)
        )

        findings.extend(
            self.rule_engine.check_missing_s3_versioning(resources)
        )

        findings.extend(
            self.rule_engine.check_unencrypted_ebs(resources)
        )

        findings.extend(
            self.rule_engine.check_missing_cloudtrail(resources)
        )

        return findings