class RuleEngine:

    def check_public_s3(self, resources):

        findings = []

        for resource in resources:

            if (
                resource["resource_type"]
                == "aws_s3_bucket_public_access_block"
            ):

                config = resource["configuration"]

                if (
                    config.get("block_public_acls") == False
                    or
                    config.get("block_public_policy") == False
                    or
                    config.get("ignore_public_acls") == False
                    or
                    config.get("restrict_public_buckets") == False
                ):

                    findings.append(
                        {
                            "rule_id": "RULE_001",
                            "severity": "HIGH",
                            "resource_name":
                                resource["resource_name"],
                            "finding":
                                "Public S3 Bucket Detected"
                        }
                    )

        return findings

    def check_open_security_groups(self, resources):

        findings = []

        for resource in resources:

            if (
                resource["resource_type"]
                == "aws_security_group"
            ):

                config = resource["configuration"]

                ingress_rules = config.get("ingress", [])

                for ingress in ingress_rules:

                    cidr_blocks = ingress.get("cidr_blocks", [])

                    for cidr in cidr_blocks:

                        if cidr == '"0.0.0.0/0"':

                            findings.append(
                                {
                                    "rule_id": "RULE_002",
                                    "severity": "MEDIUM",
                                    "resource_name":
                                        resource["resource_name"],
                                    "finding":
                                        "Security Group allows inbound access from anywhere"
                                }
                            )

                            break

        return findings
    def check_open_ssh(self, resources):

        findings = []

        for resource in resources:

            if resource["resource_type"] == "aws_security_group":

                config = resource["configuration"]

                ingress_rules = config.get("ingress", [])

                for ingress in ingress_rules:

                    from_port = ingress.get("from_port")

                    cidr_blocks = ingress.get("cidr_blocks", [])

                    if from_port == 22:

                        for cidr in cidr_blocks:

                            if cidr == '"0.0.0.0/0"':

                                findings.append(
                                    {
                                        "rule_id": "RULE_003",
                                        "severity": "HIGH",
                                        "resource_name": resource["resource_name"],
                                        "finding": "SSH Port (22) is exposed to the Internet"
                                    }
                                )

                                break

        return findings