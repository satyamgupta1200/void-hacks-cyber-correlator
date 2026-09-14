"""Streamlit UI Application Launcher."""

import streamlit as st
from ui.dashboard import render_dashboard


def main() -> None:
    st.set_page_config(
        page_title="Forensic Correlator | Void Hacks 8.0",
        page_icon="🛡️",
        layout="wide",
    )
    render_dashboard()


if __name__ == "__main__":
    main()
