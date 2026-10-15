from __future__ import annotations
import json
import os
from datetime import datetime, timezone
import streamlit as st
from phishing_core import analyze_message

st.set_page_config(page_title="PhishLens | AI Phishing Triage", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {max-width: 1180px; padding-top: 1.8rem; padding-bottom: 3rem;}
.hero {padding: 1.2rem 1.4rem; border: 1px solid rgba(128,128,128,.28); border-radius: 16px; margin-bottom: 1rem;}
.kicker {font-size:.82rem; text-transform:uppercase; letter-spacing:.14em; opacity:.72; font-weight:700;}
.muted {opacity:.72; font-size:.92rem;}
.stButton button {border-radius: 10px; font-weight: 650;}
</style>
""", unsafe_allow_html=True)

EXAMPLES = {
    "Suspicious bank text": "SECURITY ALERT: Your bank account will be suspended today. Verify your account immediately at http://secure-bank-verify.example.xyz/login and reply with your OTP to avoid account closure.",
    "Suspicious delivery notice": "Delivery failed. Pay a small redelivery fee now at https://bit.ly/delivery-check or your parcel will be returned. Payment required within 30 minutes.",
    "Possible legitimate reminder": "Reminder: Your appointment is scheduled for Friday at 10:00 AM. Please call the clinic using the number on your appointment card if you need to reschedule.",
    "Prize lure": "Congratulations! You have won a prize. Claim your prize money today by sending your bank details and security code to prize-claims@example.xyz.",
    "Blank / custom message": "",
}
if "message_text" not in st.session_state:
    st.session_state.message_text = EXAMPLES["Suspicious bank text"]
if "chosen_sample" not in st.session_state:
    st.session_state.chosen_sample = "Suspicious bank text"

def load_sample() -> None:
    st.session_state.message_text = EXAMPLES[st.session_state.sample_picker]
    st.session_state.chosen_sample = st.session_state.sample_picker

st.markdown("""
<div class="hero">
 <div class="kicker">Open-source defensive AI • Hacktoberfest Hack Day Pune</div>
 <h1 style="margin:.35rem 0;">🛡️ PhishLens</h1>
 <p style="font-size:1.12rem; margin-bottom:.4rem;">AI-powered phishing detection and explanation</p>
 <p class="muted" style="margin-bottom:0;">Inspect message text, surface explainable risk signals, and get safer next steps — without opening links or attachments.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Analysis settings")
    provider_choice = st.selectbox("Analysis engine", ["Offline demo (rules only)", "Local Gemma via Ollama", "Hosted Gemma API"], help="Offline mode works without a model. Use a Gemma option for model-generated explanation.")
    provider_map = {"Offline demo (rules only)": "rules", "Local Gemma via Ollama": "ollama", "Hosted Gemma API": "gemma_api"}
    default_model = os.getenv("PHISHLENS_OLLAMA_MODEL", "gemma4:e2b") if provider_choice == "Local Gemma via Ollama" else os.getenv("PHISHLENS_GEMMA_API_MODEL", "gemma-4-26b-a4b-it")
    model_name = st.text_input("Model name", value=default_model)
    if provider_choice == "Local Gemma via Ollama":
        ollama_url = st.text_input("Ollama base URL", value=os.getenv("PHISHLENS_OLLAMA_URL", "http://localhost:11434"))
        api_key = None
        st.caption("Local mode keeps message text on this machine, assuming Ollama is running locally.")
    elif provider_choice == "Hosted Gemma API":
        ollama_url = None
        api_key = st.text_input("Gemma API key", value=os.getenv("GEMMA_API_KEY", ""), type="password", help="Stored only in this session; do not paste company or personal secrets into prompts.")
        st.warning("Hosted mode sends the submitted text to the configured API. Use synthetic/demo text or only data approved for that service.")
    else:
        ollama_url = None
        api_key = None
        st.caption("Offline mode works without internet or model downloads.")
    st.divider()
    st.markdown("**Privacy by design**")
    st.caption("No user accounts, analytics, database, link-opening, or attachment execution. The app does not intentionally save submitted messages.")
    st.caption("For the office laptop: follow Infosys policies and use synthetic data only unless external tools/data are explicitly approved.")

left, right = st.columns([1.45, 1], gap="large")
with left:
    st.subheader("Analyze a message")
    st.selectbox("Load a sample", list(EXAMPLES.keys()), key="sample_picker", on_change=load_sample)
    message = st.text_area("Paste message text", height=230, key="message_text", placeholder="Paste a suspicious email, SMS, or chat message here…", help="Do not include confidential information, passwords, one-time codes, or real customer data.")
    st.caption(f"{len(message):,} characters • Input limit: 8,000 characters sent to the model")
    analyze_btn = st.button("Analyze message", type="primary", use_container_width=True)
    if analyze_btn:
        if not message.strip():
            st.error("Enter a message or choose a sample before analyzing.")
        elif len(message) > 20000:
            st.error("This demo accepts up to 20,000 characters. Please shorten the message.")
        else:
            with st.spinner("Reviewing signals…"):
                result_obj = analyze_message(message, provider_map[provider_choice], api_key=api_key, model=model_name, ollama_url=ollama_url)
                st.session_state["last_result"] = result_obj.to_dict()
                st.session_state["last_message"] = message
                st.session_state["last_time"] = datetime.now(timezone.utc).isoformat()

with right:
    st.subheader("What PhishLens checks")
    st.markdown("""
    - Credential and one-time-code requests
    - Urgency, threats, and social-engineering language
    - Payment or prize lures
    - URL structure, shorteners, IP destinations, and unusual domains
    - Unsafe attachment or macro instructions
    """)
    st.info("A score is a triage signal, not proof. PhishLens never opens links or declares a message safe based only on a low score.")

result = st.session_state.get("last_result")
if result:
    st.divider()
    st.subheader("Analysis report")
    score, level = int(result["score"]), result["risk_level"]
    col1, col2, col3 = st.columns([1, 1, 1.6])
    col1.metric("Heuristic risk score", f"{score}/100")
    col2.metric("Risk band", level)
    col3.metric("AI analysis source", result["ai_provider"])
    st.progress(score / 100)
    st.caption("Score is calculated by transparent local rules. AI explanation does not change this score.")
    if level == "High":
        st.error("High risk signal — verify independently before taking action.")
    elif level == "Medium":
        st.warning("Medium risk signal — review the indicators and verify the sender.")
    else:
        st.success("Low risk signal — not a guarantee of legitimacy.")
    tab1, tab2, tab3, tab4 = st.tabs(["Explanation", "Detected indicators", "URLs found", "Export report"])
    with tab1:
        st.markdown(result["ai_explanation"])
        st.caption(f"Provider: {result['ai_provider']} • Model: {result['model_used']}")
    with tab2:
        findings = result["findings"]
        if not findings:
            st.success("No indicators in the current rule set were detected. This does not prove the message is safe.")
        for finding in findings:
            with st.expander(f"{finding['title']} · +{finding['points']} points"):
                st.write(finding["detail"])
                st.caption(f"Category: {finding['category']}")
        st.markdown("**Recommended next steps**")
        for action in result["recommended_actions"]:
            st.markdown(f"- {action}")
    with tab3:
        if result["urls"]:
            st.warning("These URLs were extracted as text only. They have not been opened or checked online.")
            for url in result["urls"]:
                st.code(url, language=None)
        else:
            st.write("No URLs detected in the message text.")
    with tab4:
        report = {"application": "PhishLens", "generated_at_utc": st.session_state.get("last_time"), "submitted_message": st.session_state.get("last_message", ""), **result}
        st.download_button("Download JSON report", data=json.dumps(report, indent=2, ensure_ascii=False), file_name="phishlens-report.json", mime="application/json")
        st.caption("Report export includes the pasted message. Store it only where appropriate.")
    with st.expander("Limitations & responsible use"):
        for limitation in result["limitations"]:
            st.markdown(f"- {limitation}")
        st.markdown("- False positives and false negatives are possible. This tool is not a substitute for security controls or professional incident response.")
else:
    st.divider()
    st.subheader("Quick demo")
    st.write("Choose a sample message, select **Analyze message**, then compare the indicators and recommendations. Try the legitimate reminder to see how a low score is communicated without calling it safe.")

st.divider()
st.caption("PhishLens • Hackathon prototype • Open-source defensive security tool • Do not use it to process confidential or unapproved data.")
