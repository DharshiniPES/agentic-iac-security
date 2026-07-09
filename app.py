import os
import tempfile

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.scanner import run_scan
from reports.pdf_generator import generate_pdf
from database.db_manager import DatabaseManager
from datetime import datetime

st.set_page_config(
    page_title="Agentic IaC Security Scanner",
    layout="wide"
)
db = DatabaseManager()
st.title("Agentic IaC Security Scanner")

st.caption(
    "Infrastructure-as-Code Security Assessment Platform"
)

st.divider()

uploaded_files = st.file_uploader(
    "Upload Terraform Files",
    type=["tf"],
    accept_multiple_files=True
)

if st.button("Run Security Scan"):

    findings = []

    if uploaded_files:

        with tempfile.TemporaryDirectory() as temp_dir:

            for file in uploaded_files:

                filepath = os.path.join(
                    temp_dir,
                    file.name
                )

                with open(filepath, "wb") as f:
                    f.write(file.getbuffer())

            findings = run_scan(temp_dir)

    else:

        findings = run_scan("terraform_samples")

    st.session_state["findings"] = findings
    db.save_scan(
        findings,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

if "findings" in st.session_state:

    findings = st.session_state["findings"]

    if findings:

        df = pd.DataFrame(findings)

        st.success(
            f"Scan completed successfully. {len(df)} findings detected."
        )


        st.divider()

        overall_risk = round(df["risk_score"].mean())
        st.subheader("Executive Summary")

        if overall_risk >= 75:
            overall = "HIGH"

        elif overall_risk >= 50:
            overall = "MEDIUM"

        else:
            overall = "LOW"

        st.info(f"""
        Scan completed successfully.

        Files Scanned: {len(uploaded_files) if uploaded_files else "terraform_samples"}

        Total Findings: {len(df)}

        Overall Risk Level: {overall}

        Immediate remediation is recommended for HIGH and CRITICAL findings.
        """)
        critical = len(df[df["severity"] == "CRITICAL"])
        high = len(df[df["severity"] == "HIGH"])
        medium = len(df[df["severity"] == "MEDIUM"])
        low = len(df[df["severity"] == "LOW"])

        c1, c2, c3, c4, c5 = st.columns(5)

        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=overall_risk,
                title={"text": "Overall Risk Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "darkred"},
                    "steps": [
                        {"range": [0, 25], "color": "#2ecc71"},
                        {"range": [25, 50], "color": "#f1c40f"},
                        {"range": [50, 75], "color": "#e67e22"},
                        {"range": [75, 100], "color": "#e74c3c"},
                    ],
                },
            )
        )

        c1.plotly_chart(
            gauge,
            use_container_width=True
        )

        c2.metric("Critical", critical)
        c3.metric("High", high)
        c4.metric("Medium", medium)
        c5.metric("Low", low)

        st.divider()

        st.subheader("Security Overview")

        col1, col2 = st.columns(2)

        severity_counts = (
            df["severity"]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        pie = px.pie(
            severity_counts,
            names="Severity",
            values="Count",
            title="Severity Distribution"
        )

        bar = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            title="Findings by Severity"
        )

        col1.plotly_chart(
            pie,
            use_container_width=True
        )

        col2.plotly_chart(
            bar,
            use_container_width=True
        )

        st.divider()

        st.subheader("Security Findings")

        display_df = df.rename(
            columns={
                "rule_id": "Rule",
                "severity": "Severity",
                "resource_name": "Resource",
                "finding": "Finding",
                "risk_score": "Risk Score"
            }
        )[
            [
                "Rule",
                "Severity",
                "Resource",
                "Finding",
                "Risk Score"
            ]
        ]

        styled_df = display_df.style.map(
            lambda x:
                "background-color:#ff4b4b;color:white"
                if x=="CRITICAL"
                else
                "background-color:#ff944d;color:white"
                if x=="HIGH"
                else
                "background-color:#ffd966;color:black"
                if x=="MEDIUM"
                else
                "background-color:#90ee90;color:black",
            subset=["Severity"]
        )

        st.dataframe(
            styled_df,
            use_container_width=True
        )

        selected = st.selectbox(
            "Select a Finding",
            options=df.index,
            format_func=lambda i:
                f"{df.loc[i,'rule_id']} | "
                f"{df.loc[i,'resource_name']} | "
                f"{df.loc[i,'severity']}"
        )

        st.divider()

        st.subheader("Finding Details")

        st.markdown(
            f"**Rule ID:** {df.loc[selected,'rule_id']}"
        )

        st.markdown(
            f"**Severity:** {df.loc[selected,'severity']}"
        )

        st.markdown(
            f"**Resource:** {df.loc[selected,'resource_name']}"
        )

        st.markdown(
            f"**Risk Score:** {df.loc[selected,'risk_score']}/100"
        )

        st.markdown("### Finding")

        st.write(df.loc[selected, "finding"])

        st.markdown("### Explanation")

        st.write(df.loc[selected, "explanation"])

        st.markdown("### Recommendation")

        st.success(
            df.loc[selected, "recommendation"]
        )

        st.divider()

        pdf = generate_pdf(findings)

        st.download_button(
            label="Download Security Report",
            data=pdf,
            file_name="Security_Assessment_Report.pdf",
            mime="application/pdf"
        )

    else:

        st.warning(
            "No security findings detected."
        )
st.divider()

st.subheader("Previous Scan History")

history = db.get_all_scans()

if history:

    history_df = pd.DataFrame(
        history,
        columns=[
            "ID",
            "Scan Time",
            "Rule ID",
            "Severity",
            "Resource",
            "Finding",
            "Risk Score"
        ]
    )

    st.dataframe(
        history_df,
        use_container_width=True
    )