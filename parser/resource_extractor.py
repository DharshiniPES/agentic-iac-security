class ResourceExtractor:

    def __init__(self, terraform_data):
        self.terraform_data = terraform_data

    def clean_string(self, value):

        if isinstance(value, str):
            return value.replace('"', '')

        return value

    def extract_resources(self):

        resources = []

        if "resource" not in self.terraform_data:
            return resources

        for resource_block in self.terraform_data["resource"]:

            for resource_type, resource_instances in resource_block.items():

                resource_type = self.clean_string(resource_type)

                for resource_name, configuration in resource_instances.items():

                    clean_resource_name = resource_name.replace('"', '')

                    resources.append(
                        {
                            "resource_type": resource_type,
                            "resource_name": resource_name,
                            "configuration":
                                configuration
                        }
                    )

        return resources