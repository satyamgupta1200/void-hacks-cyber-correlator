"""Pyvis Interactive Graph Visualizer module with dark command center styling."""

from pathlib import Path
from typing import Dict, Any, Optional
import networkx as nx
from pyvis.network import Network

COLOR_MAP = {
    "VICTIM": "#10b981",     # Emerald Green
    "MULE": "#ef4444",       # Crimson Red
    "IMEI": "#f59e0b",       # Amber Orange
    "IP_ADDRESS": "#8b5cf6", # Royal Purple
    "PHONE": "#3b82f6",      # Bright Blue
    "UPI_HANDLE": "#06b6d4", # Cyan
    "ACCOUNT": "#ec4899",    # Pink
    "APP": "#64748b",        # Slate Gray
    "DEVICE": "#475569",     # Dark Slate
}


def generate_pyvis_html(
    graph: nx.MultiDiGraph,
    output_filename: str = "outputs/graph_viz.html",
    height: str = "620px",
    width: str = "100%",
) -> str:
    """Generates an interactive Pyvis HTML visualization of the network graph.

    Args:
        graph: nx.MultiDiGraph network graph instance.
        output_filename: Target HTML file path.
        height: CSS height of graph container.
        width: CSS width of graph container.

    Returns:
        Absolute file path string of generated HTML.
    """
    net = Network(height=height, width=width, directed=True, notebook=False, bgcolor="#0b0f19", font_color="#f8fafc")

    # Configure physics for clear node separation
    net.barnes_hut(
        gravity=-6000,
        central_gravity=0.2,
        spring_length=120,
        spring_strength=0.04,
        damping=0.09,
    )

    for node_id, data in graph.nodes(data=True):
        ent_type = data.get("entity_type", "PHONE")
        norm_val = data.get("normalized_value") or data.get("raw_value") or str(node_id)
        is_victim = data.get("is_victim") or "victim" in str(node_id).lower() or "suresh" in str(node_id).lower()
        is_mule = data.get("is_mule") or "mule" in str(node_id).lower() or "fastpay" in str(node_id).lower() or "cashout" in str(node_id).lower()

        if is_victim:
            color = COLOR_MAP["VICTIM"]
            shape = "star"
            size = 28
            role_label = "🟢 Victim Target Node"
        elif is_mule:
            color = COLOR_MAP["MULE"]
            shape = "diamond"
            size = 24
            role_label = "🔴 Suspected Mule Account"
        elif ent_type == "IMEI":
            color = COLOR_MAP["IMEI"]
            shape = "square"
            size = 18
            role_label = "🟠 Telecom Device / IMEI"
        elif ent_type == "IP_ADDRESS":
            color = COLOR_MAP["IP_ADDRESS"]
            shape = "triangle"
            size = 18
            role_label = "🟣 Threat IP / Originating Network"
        else:
            color = COLOR_MAP.get(ent_type, "#64748b")
            shape = "dot"
            size = 16
            role_label = f"Artifact Entity ({ent_type})"

        title_html = (
            f"<div style='background-color:#1e293b; color:#f8fafc; padding:8px; border-radius:6px; border:1px solid #334155; font-family:sans-serif;'>"
            f"<b style='color:#38bdf8;'>Node ID:</b> {node_id}<br>"
            f"<b style='color:#38bdf8;'>Type:</b> {ent_type}<br>"
            f"<b style='color:#38bdf8;'>Value:</b> {norm_val}<br>"
            f"<b style='color:#f43f5e;'>Classification:</b> {role_label}"
            f"</div>"
        )

        net.add_node(
            node_id,
            label=norm_val if len(norm_val) <= 22 else f"{norm_val[:19]}...",
            title=title_html,
            color=color,
            shape=shape,
            size=size,
        )

    # Add edges
    for u, v, key, data in graph.edges(keys=True, data=True):
        edge_type = data.get("edge_type", "LINK")
        amt = data.get("amount_inr", 0.0)
        ts = data.get("timestamp", "")
        hop = data.get("hop_number")

        if edge_type == "FINANCIAL_TRANSFER":
            label = f"₹{amt:,.0f}" if amt else "Transfer"
            title = f"Financial Transfer: ₹{amt:,.2f}<br>Timestamp: {ts}<br>Hop Step: #{hop or 'N/A'}"
            color = "#ef4444"
            width_val = 3
        elif edge_type == "CALL_INTERACTION":
            label = f"Call ({data.get('duration_sec', 0)}s)"
            title = f"Call Interaction: {data.get('duration_sec', 0)} seconds<br>Timestamp: {ts}"
            color = "#3b82f6"
            width_val = 1.5
        else:
            label = "Identity Link"
            title = f"Cross-Reference Identity Link: {u} <-> {v}"
            color = "#475569"
            width_val = 1

        net.add_edge(u, v, label=label, title=title, color=color, width=width_val)

    out_path = Path(output_filename)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    net.save_graph(str(out_path))

    return str(out_path.resolve())
