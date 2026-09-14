"""Pytest test suite for Phase 3 UI visualizer, notice generator, and report exporter."""

from pathlib import Path
import pytest
import networkx as nx

from graph.visualizer import generate_pyvis_html
from ui.notice_generator import generate_section_91_notice
from ui.report_exporter import export_case_brief_pdf


def test_pyvis_html_generator(tmp_path):
    """Tests interactive Pyvis HTML graph rendering."""
    G = nx.MultiDiGraph()
    G.add_node("PHONE:+919845012345", entity_type="PHONE", is_victim=True)
    G.add_node("UPI_HANDLE:fastpay99@okhdfcbank", entity_type="UPI_HANDLE", is_mule=True)
    G.add_edge(
        "PHONE:+919845012345",
        "UPI_HANDLE:fastpay99@okhdfcbank",
        edge_type="FINANCIAL_TRANSFER",
        amount_inr=95000.0,
        timestamp="2024-03-15T14:33:07",
    )

    out_html = tmp_path / "test_graph.html"
    result_path = generate_pyvis_html(G, str(out_html))

    assert Path(result_path).exists()
    content = Path(result_path).read_text(encoding="utf-8")
    assert "vis-network" in content or "html" in content.lower()


def test_section_91_notice_generator():
    """Tests Section 91 CrPC notice text generation."""
    notice = generate_section_91_notice(
        case_id="CASE-104",
        officer_id="IO-KA-2024-0042",
        suspect_accounts=["HDFC-MULE1-3847"],
        total_amount=95000.0,
    )

    assert "SECTION 91 Cr.P.C." in notice
    assert "CASE-104" in notice
    assert "HDFC-MULE1-3847" in notice
    assert "95,000.00" in notice


def test_pdf_report_exporter(tmp_path):
    """Tests ReportLab PDF case brief generation."""
    pdf_out = tmp_path / "test_case_brief.pdf"
    result_pdf = export_case_brief_pdf(
        case_id="CASE-104",
        output_filepath=str(pdf_out),
    )

    assert Path(result_pdf).exists()
    assert Path(result_pdf).stat().st_size > 1000
