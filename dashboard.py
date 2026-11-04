import json
from pathlib import Path
import pandas as pd
import streamlit as st

# PAGE CONFIGURATION
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)

REPORT_FILE = Path(__file__).parent / "reports" / "threat_report.json"

# CUSTOM STYLING
st.markdown(
    """
    <style>
        .stApp {
            background-color: #0e1117;
            color: #f1f5f9;
        }

        [data-testid="stMetric"] {
            background-color: #1a2230;
            border: 1px solid #293548;
            padding: 18px;
            border-radius: 10px;
        }

        [data-testid="stMetricLabel"] {
            color: #aab7c5;
        }

        [data-testid="stMetricValue"] {
            color: #ffffff;
        }

        h1, h2, h3 {
            color: #f1f5f9;
        }

        .subtitle {
            color: #94a3b8;
            font-size: 15px;
        }

        .info-box {
            background-color: #1a2230;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3b82f6;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# LOAD JSON REPORT
@st.cache_data
def load_report(file_modified):
    with REPORT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


# DASHBOARD HEADER
st.title("🛡️ Threat Intelligence Dashboard")

st.markdown(
    '<p class="subtitle">'
    'IP reputation analysis, threat classification and OSINT enrichment'
    '</p>',
    unsafe_allow_html=True,
)

st.divider()

# REPORT VALIDATION
if not REPORT_FILE.exists():
    st.error("No threat report found. Run threat_intel.py first.")
    st.stop()

try:
    report = load_report(REPORT_FILE.stat().st_mtime)

    if not isinstance(report, list):
        st.error("The report format is invalid. Expected a JSON list.")
        st.stop()

except (json.JSONDecodeError, OSError) as error:
    st.error(f"Could not load the threat report: {error}")
    st.stop()


if not report:
    st.warning("The threat report is empty. Run an IP lookup first.")
    st.stop()

# PREPARE DATA
successful_records = [
    record for record in report
    if record.get("status") == "success"
]

invalid_count = sum(
    1 for record in report
    if record.get("status") == "invalid"
)

failed_count = sum(
    1 for record in report
    if record.get("status") == "lookup_failed"
)

classifications = ["High", "Medium", "Low", "No detections", "Unknown"]

classification_counts = {
    classification: sum(
        1 for record in successful_records
        if record.get("threat_classification", "Unknown") == classification
    )
    for classification in classifications
}

high_count = classification_counts["High"]
medium_count = classification_counts["Medium"]
low_count = classification_counts["Low"]
no_detection_count = classification_counts["No detections"]


# SUMMARY METRICS
st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total IPs", len(report))
col2.metric("Successfully Analysed", len(successful_records))
col3.metric("High Risk", high_count)
col4.metric("Lookup Issues", invalid_count + failed_count)

st.write("")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Medium Risk", medium_count)
col2.metric("Low Risk", low_count)
col3.metric("No Detections", no_detection_count)
col4.metric("Invalid Inputs", invalid_count)

st.divider()

# CLASSIFICATION CHART
st.subheader("Threat Classification")

chart_data = pd.DataFrame(
    {
        "IP Count": [
            classification_counts["High"],
            classification_counts["Medium"],
            classification_counts["Low"],
            classification_counts["No detections"],
            classification_counts["Unknown"],
        ]
    },
    index=["High", "Medium", "Low", "No detections", "Unknown"],
)

col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("#### Classification Distribution")
    st.bar_chart(chart_data, horizontal=True)

with col2:
    st.markdown("#### What the classifications mean")

    st.markdown(
        """
        <div class="info-box">
        <b>High</b> – 10 or more malicious detections.<br><br>
        <b>Medium</b> – 3 to 9 malicious detections.<br><br>
        <b>Low</b> – 1 or 2 malicious detections.<br><br>
        <b>No detections</b> – Zero malicious detections.<br><br>
        <b>Unknown</b> – Missing detection statistics.
        </div>
        """,
        unsafe_allow_html=True,
    )

st.caption(
    "These classifications use thresholds defined by this project. "
    "They are not official VirusTotal threat ratings."
)

st.divider()


# VIRUSTOTAL DETECTION STATISTICS
st.subheader("VirusTotal Detection Statistics")

total_malicious = sum(
    record.get("last_analysis_stats", {}).get("malicious", 0) or 0
    for record in successful_records
)

total_suspicious = sum(
    record.get("last_analysis_stats", {}).get("suspicious", 0) or 0
    for record in successful_records
)

total_harmless = sum(
    record.get("last_analysis_stats", {}).get("harmless", 0) or 0
    for record in successful_records
)

total_undetected = sum(
    record.get("last_analysis_stats", {}).get("undetected", 0) or 0
    for record in successful_records
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Malicious", total_malicious)
col2.metric("Suspicious", total_suspicious)
col3.metric("Harmless", total_harmless)
col4.metric("Undetected", total_undetected)

st.caption(
    "These are aggregated engine results across the analysed IP addresses. "
    "They are not unique IP counts."
)

st.divider()


# IP INVESTIGATION TABLE
st.subheader("IP Investigation")

if successful_records:

    table_data = []

    for record in successful_records:
        table_data.append(
            {
                "IP Address": record.get("ip", "N/A"),
                "Country": record.get("country", "N/A"),
                "ASN": record.get("asn", "N/A"),
                "Organisation": record.get("as_owner", "N/A"),
                "Malicious": record.get(
                    "last_analysis_stats", {}
                ).get("malicious", 0),
                "Classification": record.get(
                    "threat_classification", "Unknown"
                ),
            }
        )

    df = pd.DataFrame(table_data)

    available_classifications = [
        classification
        for classification in classifications
        if classification in df["Classification"].values
    ]

    selected_classifications = st.multiselect(
        "Filter by classification",
        options=available_classifications,
        default=available_classifications,
    )

    filtered_df = df[
        df["Classification"].isin(selected_classifications)
    ]

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        f"Showing {len(filtered_df)} of {len(df)} successfully analysed IPs."
    )

else:
    st.info("There are no successfully analysed IP addresses.")


st.divider()


# IP DETAILS
st.subheader("IP Investigation Details")

if successful_records:

    ip_options = [
        record.get("ip", "Unknown")
        for record in successful_records
    ]

    selected_ip = st.selectbox(
        "Select an IP address to investigate",
        ip_options,
    )

    selected_record = next(
        record for record in successful_records
        if record.get("ip") == selected_ip
    )

    stats = selected_record.get("last_analysis_stats", {})

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Network Information")

        st.write(f"**IP Address:** {selected_ip}")
        st.write(f"**Country:** {selected_record.get('country', 'N/A')}")
        st.write(f"**Continent:** {selected_record.get('continent', 'N/A')}")
        st.write(f"**ASN:** {selected_record.get('asn', 'N/A')}")
        st.write(f"**AS Owner:** {selected_record.get('as_owner', 'N/A')}")
        st.write(f"**Network:** {selected_record.get('network', 'N/A')}")

    with col2:
        st.markdown("#### Reputation Analysis")

        st.write(
            f"**Reputation Score:** "
            f"{selected_record.get('reputation', 'N/A')}"
        )

        st.write(
            f"**Threat Classification:** "
            f"{selected_record.get('threat_classification', 'Unknown')}"
        )

        st.write(f"**Malicious:** {stats.get('malicious', 'N/A')}")
        st.write(f"**Suspicious:** {stats.get('suspicious', 'N/A')}")
        st.write(f"**Harmless:** {stats.get('harmless', 'N/A')}")
        st.write(f"**Undetected:** {stats.get('undetected', 'N/A')}")

    with st.expander("View complete IP report"):
        st.json(selected_record)


st.divider()



# INVALID AND FAILED LOOKUPS
if invalid_count or failed_count:

    with st.expander("Invalid inputs and failed lookups"):

        for record in report:
            if record.get("status") in ["invalid", "lookup_failed"]:
                st.write(
                    f"**{record.get('ip', 'Unknown')}** — "
                    f"{record.get('status')}"
                )


# DOWNLOAD REPORT
st.subheader("Export Report")

report_json = json.dumps(report, indent=4)

st.download_button(
    label="Download JSON Threat Report",
    data=report_json,
    file_name="threat_report.json",
    mime="application/json",
)

st.divider()

# FOOTER
st.caption(
    "Threat Intelligence & OSINT Enrichment Tool | "
    "Powered by Python, Streamlit and VirusTotal"
)

st.caption(
    "For investigation and educational purposes. "
    "A lack of detections does not guarantee that an IP address is safe."
)
