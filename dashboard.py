import streamlit as st
import sqlite3
import pandas as pd

DB_PATH = "logs/llmguard.db"


def load_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
    conn.close()
    return df


st.set_page_config(page_title="LLMGuard Dashboard", layout="wide")

st.title("🛡️ LLMGuard Security Dashboard")

df = load_data()

if df.empty:
    st.warning("No logs found yet.")
    st.stop()

# --- Metrics ---
total_requests = len(df)
blocked = df[df["blocked"] == 1].shape[0]
sanitized = df[df["action"] == "sanitize"].shape[0]
allowed = df[df["action"] == "allow"].shape[0]

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Requests", total_requests)
col2.metric("Allowed", allowed)
col3.metric("Sanitized", sanitized)
col4.metric("Blocked", blocked)

st.divider()

# --- Risk Score Chart ---
st.subheader("Risk Score Distribution")
st.bar_chart(df["risk_score"])

st.divider()

# --- Action Distribution ---
st.subheader("Action Breakdown")
st.write(df["action"].value_counts())

st.divider()

# --- Logs Table ---
st.subheader("Recent Logs")
st.dataframe(df, use_container_width=True)