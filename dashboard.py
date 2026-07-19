import streamlit as st
import json

st.set_page_config(page_title="AWS Compliance Scanner", layout="wide")

st.title("☁️ AWS Cloud Security Compliance Dashboard")

# Load the results from your scan
with open('scan_results.json', 'r') as f:
    results = json.load(f)

# ===== SUMMARY COUNTS =====
total = len(results)
passed = len([r for r in results if r['status'] == 'PASS'])
failed = len([r for r in results if r['status'] == 'FAIL'])
warnings = len([r for r in results if r['status'] == 'WARNING'])

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Checks", total)
col2.metric("Passed", passed)
col3.metric("Failed", failed)
col4.metric("Warnings", warnings)

st.divider()

# ===== DETAILED RESULTS =====
st.subheader("Detailed Findings")

for finding in results:
    status = finding['status']
    
    if status == "FAIL":
        icon = "🔴"
    elif status == "WARNING":
        icon = "🟡"
    elif status == "PASS":
        icon = "🟢"
    else:
        icon = "⚪"
    
    st.write(f"{icon} **{finding['check']}** — `{finding['resource']}`")
    st.caption(f"{status}: {finding['message']}")