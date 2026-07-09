from parser.terraform_parser import TerraformParser
from parser.resource_extractor import ResourceExtractor
from detection.detector import DetectionEngine
from risk.risk_scoring import RiskScoringEngine
from explainability.ai_explainer import ExplainabilityEngine
from remediation.recommendation_engine import RecommendationEngine


def run_scan(folder_path):

    parser = TerraformParser(folder_path)

    terraform_data = parser.parse()

    extractor = ResourceExtractor(terraform_data)

    resources = extractor.extract_resources()

    detector = DetectionEngine()

    findings = detector.run_detection(resources)

    findings = RiskScoringEngine().calculate_risk(findings)

    findings = ExplainabilityEngine().generate_explanations(findings)

    findings = RecommendationEngine().generate_recommendations(findings)

    return findings