import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.analyzers.risk_scorer import score_findings
from backend.analyzers.misconfiguration_detector import get_mock_findings
from backend.rag.knowledge_base import get_remediation, search_knowledge_base


def test_risk_score_empty():
    result = score_findings([])
    assert result["score"] == 0
    assert result["grade"] == "A"


def test_risk_score_critical():
    findings = [{"severity": "critical"} for _ in range(5)]
    result = score_findings(findings)
    assert result["score"] == 100
    assert result["grade"] == "F"


def test_mock_findings_not_empty():
    data = get_mock_findings()
    assert len(data["findings"]) > 0
    assert data["grade"] in ("A", "B", "C", "D", "F")


def test_remediation_lookup():
    guide = get_remediation("s3_public_access")
    assert "steps" in guide
    assert len(guide["steps"]) > 0


def test_knowledge_base_search():
    results = search_knowledge_base("s3 encryption bucket")
    assert len(results) > 0


def test_knowledge_base_no_match():
    results = search_knowledge_base("xyzzy nonsense irrelevant")
    assert isinstance(results, list)


if __name__ == "__main__":
    test_risk_score_empty()
    test_risk_score_critical()
    test_mock_findings_not_empty()
    test_remediation_lookup()
    test_knowledge_base_search()
    test_knowledge_base_no_match()
    print("All tests passed.")
