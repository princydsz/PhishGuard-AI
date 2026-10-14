"""Cybersecurity-themed CSS styling and UI components for Streamlit."""

import streamlit as st


def apply_cyber_theme():
    """Inject premium dark navy and cyber-cyan CSS styles into the Streamlit app."""
    css = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    /* Global Root and Base Elements */
    :root {
        --bg-main: #070B14;
        --bg-card: rgba(15, 23, 42, 0.75);
        --bg-card-hover: rgba(22, 36, 68, 0.85);
        --border-color: rgba(56, 189, 248, 0.2);
        --border-glow: rgba(0, 229, 255, 0.4);
        --accent-cyan: #00E5FF;
        --accent-blue: #38BDF8;
        --text-primary: #F8FAFC;
        --text-secondary: #94A3B8;
        --danger: #EF4444;
        --warning: #F59E0B;
        --success: #10B981;
    }

    html, body, [class*="css"] {
        font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Main Container Background */
    .stApp {
        background: radial-gradient(circle at 10% 20%, #0d1527 0%, #070B14 90%) !important;
        color: var(--text-primary) !important;
    }

    /* Sidebar Customization */
    section[data-testid="stSidebar"] {
        background-color: #0A0F1D !important;
        border-right: 1px solid rgba(56, 189, 248, 0.15);
    }
    section[data-testid="stSidebar"] div.stRadio > label {
        color: var(--accent-cyan) !important;
        font-weight: 600;
        letter-spacing: 0.5px;
    }

    /* Metric Cards */
    .cyber-metric-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5), inset 0 0 15px rgba(0, 229, 255, 0.03);
        backdrop-filter: blur(12px);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }
    .cyber-metric-card:hover {
        transform: translateY(-2px);
        border-color: var(--accent-cyan);
        box-shadow: 0 8px 30px rgba(0, 229, 255, 0.15);
    }
    .cyber-metric-title {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: var(--text-secondary);
        font-weight: 500;
        margin-bottom: 8px;
    }
    .cyber-metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #FFFFFF;
        font-family: 'JetBrains Mono', monospace;
    }
    .cyber-metric-sub {
        font-size: 0.8rem;
        color: var(--accent-cyan);
        margin-top: 6px;
    }

    /* Alert and Badge styles */
    .phish-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-danger {
        background: rgba(239, 68, 68, 0.18);
        border: 1px solid #EF4444;
        color: #FCA5A5;
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.2);
    }
    .badge-warning {
        background: rgba(245, 158, 11, 0.18);
        border: 1px solid #F59E0B;
        color: #FCD34D;
        box-shadow: 0 0 10px rgba(245, 158, 11, 0.2);
    }
    .badge-success {
        background: rgba(16, 185, 129, 0.18);
        border: 1px solid #10B981;
        color: #6EE7B7;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.2);
    }
    .badge-neutral {
        background: rgba(148, 163, 184, 0.15);
        border: 1px solid #64748B;
        color: #CBD5E1;
    }

    /* Indicator item card */
    .indicator-box {
        background: rgba(15, 23, 42, 0.6);
        border-left: 4px solid var(--accent-cyan);
        border-top: 1px solid rgba(56, 189, 248, 0.1);
        border-right: 1px solid rgba(56, 189, 248, 0.1);
        border-bottom: 1px solid rgba(56, 189, 248, 0.1);
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    .indicator-box.high-severity {
        border-left-color: #EF4444;
    }
    .indicator-box.medium-severity {
        border-left-color: #F59E0B;
    }
    .indicator-box.low-severity {
        border-left-color: #38BDF8;
    }

    /* AI Insight card */
    .ai-card {
        background: linear-gradient(135deg, rgba(16, 27, 56, 0.8) 0%, rgba(9, 14, 28, 0.9) 100%);
        border: 1px solid rgba(0, 229, 255, 0.3);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 0 25px rgba(0, 229, 255, 0.08);
        margin: 16px 0;
    }

    /* Code & Preformatted Text */
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: #0A0F1D !important;
        color: #38BDF8 !important;
        border-radius: 4px;
    }

    /* Streamlit Buttons */
    div.stButton > button {
        background: linear-gradient(135deg, #0284C7 0%, #0369A1 100%) !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border: 1px solid rgba(56, 189, 248, 0.5) !important;
        border-radius: 8px !important;
        padding: 0.55rem 1.2rem !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 4px 12px rgba(2, 132, 199, 0.25) !important;
    }
    div.stButton > button:hover {
        background: linear-gradient(135deg, #0EA5E9 0%, #0284C7 100%) !important;
        border-color: #00E5FF !important;
        box-shadow: 0 0 16px rgba(0, 229, 255, 0.45) !important;
        transform: translateY(-1px);
    }

    /* Streamlit Text Inputs and Text Areas */
    div.stTextInput > div > div > input,
    div.stTextArea > div > div > textarea {
        background-color: #0B132B !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(56, 189, 248, 0.25) !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace;
    }
    div.stTextInput > div > div > input:focus,
    div.stTextArea > div > div > textarea:focus {
        border-color: #00E5FF !important;
        box-shadow: 0 0 10px rgba(0, 229, 255, 0.3) !important;
    }

    /* Table styling */
    .styled-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.9rem;
        background: rgba(15, 23, 42, 0.5);
        border-radius: 8px;
        overflow: hidden;
    }
    .styled-table th {
        background-color: rgba(30, 41, 59, 0.8);
        color: var(--accent-cyan);
        text-align: left;
        padding: 12px 14px;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.8px;
    }
    .styled-table td {
        padding: 12px 14px;
        border-bottom: 1px solid rgba(56, 189, 248, 0.1);
        color: var(--text-primary);
    }
    .styled-table tr:hover {
        background-color: rgba(56, 189, 248, 0.05);
    }
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def render_metric_card(title: str, value: str, subtext: str = "", delta_color: str = "cyan"):
    """Render a styled cyber metric card."""
    color_style = "var(--accent-cyan)"
    if delta_color == "danger":
        color_style = "var(--danger)"
    elif delta_color == "warning":
        color_style = "var(--warning)"
    elif delta_color == "success":
        color_style = "var(--success)"

    card_html = f"""
    <div class="cyber-metric-card">
        <div class="cyber-metric-title">{title}</div>
        <div class="cyber-metric-value">{value}</div>
        {f'<div class="cyber-metric-sub" style="color: {color_style};">{subtext}</div>' if subtext else ''}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_verdict_badge(verdict: str, probability_text: str = ""):
    """Render a verdict badge (PHISHING, SUSPICIOUS, LEGITIMATE)."""
    verdict_upper = verdict.upper()
    if "PHISH" in verdict_upper or "MALICIOUS" in verdict_upper or "HIGH" in verdict_upper:
        badge_class = "badge-danger"
        icon = "🚨"
    elif "SUSPICIOUS" in verdict_upper or "MEDIUM" in verdict_upper or "WARNING" in verdict_upper:
        badge_class = "badge-warning"
        icon = "⚠️"
    else:
        badge_class = "badge-success"
        icon = "🛡️"

    prob_suffix = f" &bull; {probability_text}" if probability_text else ""
    st.markdown(
        f"""
        <div style="margin: 12px 0;">
            <span class="phish-badge {badge_class}">
                {icon} {verdict.upper()}{prob_suffix}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )
