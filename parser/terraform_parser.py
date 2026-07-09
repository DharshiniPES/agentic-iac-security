import hcl2

from parser.resource_extractor import ResourceExtractor
from detection.detector import DetectionEngine
from risk.risk_scoring import RiskScoringEngine
from explainability.ai_explainer import ExplainabilityEngine
from remediation.recommendation_engine import RecommendationEngine
class TerraformParser:

    def __init__(self, filepath):
        self.filepath = filepath

    def parse(self):

        with open(self.filepath, "r") as file:

            content = file.read()

            print(content)

            file.seek(0)

            terraform_data = hcl2.load(file)

        return terraform_data


if __name__ == "__main__":

    parser = TerraformParser(
        "terraform_samples/security_groups.tf"
    )

    terraform_data = parser.parse()

    extractor = ResourceExtractor(terraform_data)

    resources = extractor.extract_resources()

    from pprint import pprint

    print("\n=== EXTRACTED RESOURCES ===")
    pprint(resources)

    detector = DetectionEngine()

    findings = detector.run_detection(resources)

    print(findings)

    risk_engine = RiskScoringEngine()

    scored_findings = risk_engine.calculate_risk(
        findings
    )

    print(scored_findings)

    explainer = ExplainabilityEngine()

    explained_findings = (
        explainer.generate_explanations(
            scored_findings
        )
    )

    print(explained_findings)

    recommendation_engine = (
        RecommendationEngine()
    )

    final_findings = (
        recommendation_engine
        .generate_recommendations(
            explained_findings
        )
    )

    print(final_findings)