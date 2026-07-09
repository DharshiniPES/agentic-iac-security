from io import BytesIO
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf(findings):

    if findings is None:
        return b""

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    # =====================================================
    # Title
    # =====================================================

    elements.append(
        Paragraph(
            "Agentic IaC Security Scanner",
            styles["Title"]
        )
    )

    elements.append(
        Paragraph(
            "Infrastructure-as-Code Security Assessment Report",
            styles["Heading2"]
        )
    )

    elements.append(Spacer(1, 20))

    # =====================================================
    # Executive Summary
    # =====================================================

    overall_risk = round(
        sum(f["risk_score"] for f in findings) / len(findings)
    )

    critical = len(
        [f for f in findings if f["severity"] == "CRITICAL"]
    )

    high = len(
        [f for f in findings if f["severity"] == "HIGH"]
    )

    medium = len(
        [f for f in findings if f["severity"] == "MEDIUM"]
    )

    low = len(
        [f for f in findings if f["severity"] == "LOW"]
    )

    if overall_risk >= 75:
        overall_level = "HIGH"

    elif overall_risk >= 50:
        overall_level = "MEDIUM"

    else:
        overall_level = "LOW"

    elements.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Date:</b> {datetime.now().strftime('%d %B %Y %H:%M')}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Total Findings:</b> {len(findings)}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Overall Risk Score:</b> {overall_risk}/100",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Overall Risk Level:</b> {overall_level}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Critical:</b> {critical}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>High:</b> {high}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Medium:</b> {medium}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Low:</b> {low}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 25))

    # =====================================================
    # Detailed Findings
    # =====================================================

    elements.append(
        Paragraph(
            "Detailed Security Findings",
            styles["Heading1"]
        )
    )

    elements.append(Spacer(1, 15))

    for i, finding in enumerate(findings, start=1):

        elements.append(
            Paragraph(
                f"<b>Finding {i}</b>",
                styles["Heading2"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Rule ID:</b> {finding['rule_id']}",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Severity:</b> {finding['severity']}",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Risk Score:</b> {finding['risk_score']}/100",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Resource:</b> {finding['resource_name']}",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Finding:</b> {finding['finding']}",
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Explanation:</b>",
                styles["Heading3"]
            )
        )

        elements.append(
            Paragraph(
                finding["explanation"],
                styles["Normal"]
            )
        )

        elements.append(
            Paragraph(
                f"<b>Recommendation:</b>",
                styles["Heading3"]
            )
        )

        elements.append(
            Paragraph(
                finding["recommendation"],
                styles["Normal"]
            )
        )

        elements.append(Spacer(1, 20))

    # =====================================================
    # Footer
    # =====================================================

    elements.append(PageBreak())

    elements.append(
        Paragraph(
            "End of Security Assessment Report",
            styles["Heading2"]
        )
    )

    elements.append(
        Paragraph(
            "Generated automatically by the Agentic IaC Security Scanner.",
            styles["Normal"]
        )
    )

    doc.build(elements)

    pdf = buffer.getvalue()

    buffer.close()

    return pdf