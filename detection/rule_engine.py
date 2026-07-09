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
    def check_iam_wildcards(self, resources):

        findings = []

        for resource in resources:

            if resource["resource_type"] == "aws_iam_policy":

                config = resource["configuration"]

                policy = config.get("policy", "")

                if 'Action = "*"' in policy:

                    findings.append(
                        {
                            "rule_id": "RULE_004",
                            "severity": "CRITICAL",
                            "resource_name": resource["resource_name"],
                            "finding": "IAM Policy contains wildcard Action (*)"
                        }
                    )

        return findings
    
    def check_missing_s3_encryption(self, resources):

        findings = []

        encryption_resources = []

        for resource in resources:

            if (
                resource["resource_type"]
                == "aws_s3_bucket_server_side_encryption_configuration"
            ):

                encryption_resources.append(
                    resource["configuration"].get("bucket")
                )

        for resource in resources:

            if resource["resource_type"] == "aws_s3_bucket":

                bucket_name = resource["configuration"].get("bucket")

                if bucket_name not in encryption_resources:

                    findings.append(
                        {
                            "rule_id": "RULE_005",
                            "severity": "HIGH",
                            "resource_name": resource["resource_name"],
                            "finding": "S3 Bucket does not have server-side encryption enabled"
                        }
                    )

        return findings
    def check_missing_s3_versioning(self, resources):

        findings = []

        versioning_resources = []

        for resource in resources:

            if (
                resource["resource_type"]
                == "aws_s3_bucket_versioning"
            ):

                versioning_resources.append(
                    resource["configuration"].get("bucket")
                )

        for resource in resources:

            if resource["resource_type"] == "aws_s3_bucket":

                bucket_name = resource["configuration"].get("bucket")

                if bucket_name not in versioning_resources:

                    findings.append(
                        {
                            "rule_id": "RULE_006",
                            "severity": "MEDIUM",
                            "resource_name": resource["resource_name"],
                            "finding": "S3 Bucket does not have versioning enabled"
                        }
                    )

        return findings
    def check_unencrypted_ebs(self, resources):

        findings = []

        for resource in resources:

            if resource["resource_type"] == "aws_ebs_volume":

                config = resource["configuration"]

                if config.get("encrypted") == False:

                    findings.append(
                        {
                            "rule_id": "RULE_007",
                            "severity": "HIGH",
                            "resource_name": resource["resource_name"],
                            "finding": "EBS Volume is not encrypted"
                        }
                    )

        return findings
    def check_missing_cloudtrail(self, resources):

        findings = []

        cloudtrail_exists = False

        for resource in resources:

            if resource["resource_type"] == "aws_cloudtrail":

                cloudtrail_exists = True

                break

        if not cloudtrail_exists:

            findings.append(
                {
                    "rule_id": "RULE_008",
                    "severity": "HIGH",
                    "resource_name": "AWS Environment",
                    "finding": "CloudTrail logging is not enabled"
                }
            )

        return findings