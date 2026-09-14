"""Pytest test suite for Forensic Copilot and Context Builder."""

from pathlib import Path
import pytest

from mock_data.generator import generate_case_104_data
from parsers.cdr_parser import CDRParser
from parsers.bank_parser import BankParser
from parsers.apk_parser import APKParser
from parsers.email_parser import EmailParser
from engine.entity_resolver import resolve_entities
from engine.rule_engine import RuleEngine
from copilot.context_builder import build_case_context
from copilot.langchain_agent import ForensicCopilot
from copilot.prompt_templates import PRELOADED_QUERIES


@pytest.fixture(scope="module")
def case_104_context(tmp_path_factory):
    """Fixture initializing Case 104 data and building case context."""
    data_dir = tmp_path_factory.mktemp("case_104_copilot")
    generate_case_104_data(str(data_dir))

    out_dir = data_dir / "outputs"
    p1 = CDRParser("sha1").parse(str(data_dir / "cdr_records.csv"))
    p2 = BankParser("sha2").parse(str(data_dir / "bank_statement.csv"))
    p3 = APKParser("sha3").parse(str(data_dir / "apk_dump.json"))
    p4 = EmailParser("sha4").parse(str(data_dir / "phishing_email.eml"))

    results = [p1, p2, p3, p4]
    entity_map = resolve_entities(results, str(out_dir))

    all_events = []
    for r in results:
        all_events.extend(r.events)

    RuleEngine().evaluate(entity_map, all_events, str(out_dir))
    ctx = build_case_context(str(out_dir))
    return {"context": ctx, "out_dir": out_dir}


def test_context_builder(case_104_context):
    """Tests case context generation for LLM/RAG prompting."""
    ctx = case_104_context["context"]

    assert "CASE-104" in ctx
    assert "RISK ASSESSMENT" in ctx
    assert "+919845012345" in ctx
    assert "fastpay99@okhdfcbank" in ctx
    assert "16,101.69" in ctx or "Velocity" in ctx


def test_copilot_queries(case_104_context):
    """Tests copilot query execution across all pre-loaded queries."""
    ctx = case_104_context["context"]
    copilot = ForensicCopilot()

    for q in PRELOADED_QUERIES:
        ans = copilot.query(q, ctx)
        assert len(ans) > 50
        assert "Case" in ans or "Forensic" in ans or "Mule" in ans or "SIM" in ans or "APK" in ans
