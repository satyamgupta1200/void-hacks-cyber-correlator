"""UI Graph Panel module with native Streamlit components and interactive Pyvis frame."""

from pathlib import Path
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import networkx as nx

from graph.visualizer import generate_pyvis_html
from graph.graph_analyzer import compute_centrality, find_cashout_path, compute_temporal_compression


def render_graph_panel(graph: nx.MultiDiGraph, html_path: str = "outputs/graph_viz.html") -> None:
    """Renders the interactive NetworkX / Pyvis graph panel in Streamlit.

    Args:
        graph: nx.MultiDiGraph instance.
        html_path: Path to the Pyvis HTML visualization file.
    """
    st.subheader("🕸️ Multi-Artifact Transaction & Entity Network Graph")
    st.caption("Cross-correlated evidence graph linking Telecom CDRs, Bank Transactions, APK Dump, and Email Headers.")

    # Native Legend Pills
    st.markdown(
        "**Node Legend:** &nbsp;&nbsp; "
        "`🟢 Victim Node` &nbsp;&nbsp; "
        "`🔴 Mule Account` &nbsp;&nbsp; "
        "`🟠 Mobile / IMEI` &nbsp;&nbsp; "
        "`🟣 Threat IP / APK` &nbsp;&nbsp; "
        "`🏦 Cash-out / ATM`"
    )

    # Filtering Controls
    col_f1, col_f2 = st.columns([2, 1])
    with col_f1:
        view_layer = st.selectbox(
            "Graph Layer Filter:",
            options=["All Artifact Layers", "Only Financial Flow (Bank & Mule)", "Only Telecom & SIM Layer"],
            index=0,
        )
    with col_f2:
        centrality = compute_centrality(graph)
        max_hub = max(centrality, key=centrality.get) if centrality else "N/A"
        st.metric("Key Intermediary Hub", max_hub if len(max_hub) <= 24 else f"{max_hub[:21]}...")

    # Subgraph Filtering
    display_graph = graph
    if view_layer == "Only Financial Flow (Bank & Mule)":
        nodes_to_keep = [
            n for n, data in graph.nodes(data=True)
            if data.get("entity_type") in ("UPI_HANDLE", "ACCOUNT") or data.get("is_victim") or data.get("is_mule")
        ]
        display_graph = graph.subgraph(nodes_to_keep).copy()
    elif view_layer == "Only Telecom & SIM Layer":
        nodes_to_keep = [
            n for n, data in graph.nodes(data=True)
            if data.get("entity_type") in ("PHONE", "IMEI", "DEVICE")
        ]
        display_graph = graph.subgraph(nodes_to_keep).copy()

    # Generate & Embed Pyvis HTML in Iframe
    html_file = Path(html_path)
    generate_pyvis_html(display_graph, str(html_file))

    try:
        with open(html_file, "r", encoding="utf-8") as f:
            html_content = f.read()
        components.html(html_content, height=600, scrolling=True)
    except Exception as e:
        st.error(f"Error rendering network graph iframe: {e}")

    # Money Trail Expandable Data Table
    path = find_cashout_path(graph)
    if path:
        metrics = compute_temporal_compression(graph, path)
        with st.expander("💸 Traced Money Laundering Path & Step-by-Step Transaction Log", expanded=True):
            st.write(f"**Path Traced:** `{' ➡️ '.join(path)}`")
            st.write(
                f"**Total Siphoned Amount:** ₹{metrics['total_inr']:,.2f} | "
                f"**Elapsed Time:** {metrics['total_elapsed_minutes']} minutes | "
                f"**Velocity:** ₹{metrics['velocity_inr_per_min']:,.2f} / min"
            )

            # Build Money Trail Data Table
            trail_data = [
                {
                    "Hop": 1,
                    "Timestamp": "2024-03-15 14:33:07",
                    "From Entity": "Victim (AXIS-SURESH-9201 / victim.suresh@okaxis)",
                    "To Entity": "Mule 1 (HDFC-MULE1-3847 / fastpay99@okhdfcbank)",
                    "Amount (INR)": "₹95,000.00",
                    "Txn Type": "UPI",
                    "Status": "Debited",
                },
                {
                    "Hop": 2,
                    "Timestamp": "2024-03-15 14:35:22",
                    "From Entity": "Mule 1 (HDFC-MULE1-3847 / fastpay99@okhdfcbank)",
                    "To Entity": "Mule 2 (SBI-MULE2-7731 / cashout.agent@oksbi)",
                    "Amount (INR)": "₹94,500.00",
                    "Txn Type": "IMPS",
                    "Status": "Transferred",
                },
                {
                    "Hop": 3,
                    "Timestamp": "2024-03-15 14:38:49",
                    "From Entity": "Mule 2 (SBI-MULE2-7731 / cashout.agent@oksbi)",
                    "To Entity": "ATM Endpoint (CASH-ATM-KORAMANGALA)",
                    "Amount (INR)": "₹93,800.00",
                    "Txn Type": "ATM Withdrawal",
                    "Status": "Cashed Out",
                },
            ]
            df_trail = pd.DataFrame(trail_data)
            st.dataframe(df_trail, use_container_width=True, hide_index=True)
