import os
import hcl2

from parser.resource_extractor import ResourceExtractor
from detection.detector import DetectionEngine
from risk.risk_scoring import RiskScoringEngine
from explainability.ai_explainer import ExplainabilityEngine
from remediation.recommendation_engine import RecommendationEngine


class TerraformParser:

    def __init__(self, folder_path):
        self.folder_path = folder_path

    def parse(self):

        terraform_data = {
            "resource": []
        }

        for filename in os.listdir(self.folder_path):

            if filename.endswith(".tf"):

                filepath = os.path.join(
                    self.folder_path,
                    filename
                )

                with open(filepath, "r") as file:

                    print(f"\n===== {filename} =====\n")
                    print(file.read())

                    file.seek(0)

                    parsed_data = hcl2.load(file)

                    terraform_data["resource"].extend(
                        parsed_data.get("resource", [])
                    )

        return terraform_data


if __name__ == "__main__":

    parser = TerraformParser(
        "terraform_samples"
    )

    terraform_data = parser.parse()

    extractor = ResourceExtractor(terraform_data)

    resources = extractor.extract_resources()

    from pprint import pprint

    print("\n=== EXTRACTED RESOURCES ===")
    pprint(resources)

    detector = DetectionEngine()

    findings = detector.run_detection(resources)

    print("\n=== DETECTION RESULTS ===")
    pprint(findings)

    risk_engine = RiskScoringEngine()

    scored_findings = risk_engine.calculate_risk(
        findings
    )

    print("\n=== RISK ASSESSMENT ===")
    pprint(scored_findings)

    explainer = ExplainabilityEngine()

    explained_findings = (
        explainer.generate_explanations(
            scored_findings
        )
    )

    print("\n=== EXPLANATIONS ===")
    pprint(explained_findings)

    recommendation_engine = RecommendationEngine()

    final_findings = (
        recommendation_engine.generate_recommendations(
            explained_findings
        )
    )

    print("\n=== FINAL SECURITY REPORT ===")
    pprint(final_findings)