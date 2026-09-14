"""Pytest test suite for NetworkX Graph Builder and Analyzer."""

import pickle
import pytest
import networkx as nx

from mock_data.generator import generate_case_104_data
from parsers.cdr_parser import CDRParser
from parsers.bank_parser import BankParser
from parsers.apk_parser import APKParser
from parsers.email_parser import EmailParser
from engine.entity_resolver import resolve_entities
from graph.graph_builder import build_network_graph
from graph.graph_analyzer import (
    compute_centrality,
    find_cashout_path,
    find_terminal_cashout_nodes,
    compute_temporal_compression,
)


@pytest.fixture(scope="module")
def case_104_graph(tmp_path_factory):
    """Fixture constructing NetworkX multigraph for Case 104."""
    data_dir = tmp_path_factory.mktemp("case_104_graph")
    generate_case_104_data(str(data_dir))

    p1 = CDRParser("sha_cdr").parse(str(data_dir / "cdr_records.csv"))
    p2 = BankParser("sha_bank").parse(str(data_dir / "bank_statement.csv"))
    p3 = APKParser("sha_apk").parse(str(data_dir / "apk_dump.json"))
    p4 = EmailParser("sha_email").parse(str(data_dir / "phishing_email.eml"))

    results = [p1, p2, p3, p4]
    entity_map = resolve_entities(results, str(data_dir / "outputs"))

    all_events = []
    for r in results:
        all_events.extend(r.events)

    G = build_network_graph(entity_map, p2.events, p1.events, str(data_dir / "outputs"))
    return {"graph": G, "data_dir": data_dir}


def test_graph_builder_and_pickle(case_104_graph):
    """Tests graph construction, node attributes, and graph_state.pkl serialization."""
    G = case_104_graph["graph"]
    data_dir = case_104_graph["data_dir"]

    assert isinstance(G, nx.MultiDiGraph)
    assert len(G.nodes()) > 10
    assert len(G.edges()) > 5

    pkl_file = data_dir / "outputs" / "graph_state.pkl"
    assert pkl_file.exists()

    with open(pkl_file, "rb") as f:
        loaded_G = pickle.load(f)
    assert len(loaded_G.nodes()) == len(G.nodes())


def test_graph_analyzer_path_and_temporal_compression(case_104_graph):
    """Tests shortest path tracing from Victim to Cashout and temporal compression calculation."""
    G = case_104_graph["graph"]

    centrality = compute_centrality(G)
    assert len(centrality) > 0

    terminals = find_terminal_cashout_nodes(G)
    assert len(terminals) > 0

    path = find_cashout_path(G)
    assert len(path) >= 3

    temp_metrics = compute_temporal_compression(G, path)
    assert temp_metrics["total_inr"] > 0
    assert temp_metrics["velocity_inr_per_min"] > 0
