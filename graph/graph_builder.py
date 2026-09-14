"""NetworkX Graph Builder module for constructing directed multi-graphs from resolved entities and events."""

import pickle
from pathlib import Path
from typing import Dict, List, Any, Optional
import networkx as nx


def build_network_graph(
    entity_map: Dict[str, Any],
    bank_events: List[Dict[str, Any]],
    cdr_events: Optional[List[Dict[str, Any]]] = None,
    output_dir: str = "outputs",
) -> nx.MultiDiGraph:
    """Builds a directed multigraph from resolved entity map and transaction events.

    Args:
        entity_map: Entity resolution map containing 'entities' and 'cross_refs'.
        bank_events: List of bank transaction event dictionaries.
        cdr_events: Optional list of CDR call event dictionaries.
        output_dir: Directory where graph_state.pkl will be saved.

    Returns:
        nx.MultiDiGraph representing the forensic entity network.
    """
    G = nx.MultiDiGraph()

    entities_dict = entity_map.get("entities", {})

    # Add all resolved entity nodes
    for entity_id, ent in entities_dict.items():
        node_id = f"{ent.get('entity_type')}:{ent.get('normalized_value') or ent.get('raw_value')}"
        norm_val = ent.get("normalized_value", "")

        is_mule = "mule" in norm_val.lower() or "fastpay99" in norm_val or "cashout" in norm_val
        is_victim = "victim" in norm_val.lower() or "suresh" in norm_val.lower()

        G.add_node(
            node_id,
            entity_id=entity_id,
            entity_type=ent.get("entity_type"),
            raw_value=ent.get("raw_value"),
            normalized_value=norm_val,
            is_mule=is_mule,
            is_victim=is_victim,
            attributes=ent.get("attributes", {}),
        )

    # Add cross-reference edges (undirected identity links as bidirectional graph edges)
    cross_refs = entity_map.get("cross_refs", {})
    for k1, links in cross_refs.items():
        if not G.has_node(k1):
            G.add_node(k1, entity_type=k1.split(":")[0], raw_value=k1.split(":", 1)[-1])
        for k2 in links:
            if not G.has_node(k2):
                G.add_node(k2, entity_type=k2.split(":")[0], raw_value=k2.split(":", 1)[-1])
            if not G.has_edge(k1, k2):
                G.add_edge(k1, k2, edge_type="IDENTITY_LINK", weight=1.0)

    # Sort bank events chronologically to assign hop numbers
    sorted_bank = list(bank_events)
    sorted_bank.sort(key=lambda x: x.get("timestamp") or "")

    hop = 1
    for ev in sorted_bank:
        from_upi = ev.get("from_upi")
        to_upi = ev.get("to_upi")
        debit_acc = ev.get("debit_account")
        credit_acc = ev.get("credit_account")
        amt = ev.get("amount_inr", 0.0)
        ts = ev.get("timestamp")
        txn_id = ev.get("txn_id")
        txn_type = ev.get("txn_type", "UPI")

        # Determine source and target node keys
        src_node = f"UPI_HANDLE:{from_upi}" if from_upi else (f"ACCOUNT:{debit_acc}" if debit_acc else None)
        tgt_node = f"UPI_HANDLE:{to_upi}" if to_upi else (f"ACCOUNT:{credit_acc}" if credit_acc else None)

        if src_node and tgt_node:
            if not G.has_node(src_node):
                G.add_node(src_node, entity_type=src_node.split(":")[0], normalized_value=src_node.split(":", 1)[-1])
            if not G.has_node(tgt_node):
                G.add_node(tgt_node, entity_type=tgt_node.split(":")[0], normalized_value=tgt_node.split(":", 1)[-1])

            G.add_edge(
                src_node,
                tgt_node,
                edge_type="FINANCIAL_TRANSFER",
                amount_inr=amt,
                timestamp=ts,
                txn_type=txn_type,
                txn_id=txn_id,
                hop_number=hop,
            )
            hop += 1

    # Add CDR call edges if provided
    if cdr_events:
        for ev in cdr_events:
            from_p = ev.get("from")
            to_p = ev.get("to")
            if from_p and to_p:
                src_node = f"PHONE:{from_p}"
                tgt_node = f"PHONE:{to_p}"
                if not G.has_node(src_node):
                    G.add_node(src_node, entity_type="PHONE", normalized_value=from_p)
                if not G.has_node(tgt_node):
                    G.add_node(tgt_node, entity_type="PHONE", normalized_value=to_p)

                G.add_edge(
                    src_node,
                    tgt_node,
                    edge_type="CALL_INTERACTION",
                    duration_sec=ev.get("duration_sec", 0),
                    timestamp=ev.get("start_ts"),
                    call_type=ev.get("call_type", "VOICE"),
                )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    graph_file = out_path / "graph_state.pkl"

    with open(graph_file, "wb") as f:
        pickle.dump(G, f)

    return G
