"""
RAG-based remediation engine.
Local mode: keyword search over the knowledge base.
OpenAI mode: use LLM with retrieved docs as context.
"""

import logging
from typing import Dict

from backend.rag.knowledge_base import get_remediation, search_knowledge_base

logger = logging.getLogger(__name__)


def ask(question: str, findings: list, config: dict) -> Dict:
    """Answer a remediation or infrastructure question."""
    mode = config.get("rag", {}).get("mode", "local")

    kb_results = search_knowledge_base(question)
    context_docs = [r["guide"] for r in kb_results]

    # Find relevant findings
    related_findings = _find_related_findings(question, findings)

    if mode == "openai" and config.get("rag", {}).get("openai_api_key"):
        answer = _ask_openai(question, context_docs, related_findings, config)
    else:
        answer = _local_answer(question, context_docs, related_findings)

    return {
        "question": question,
        "answer": answer,
        "sources": [r["guide"]["title"] for r in kb_results],
        "related_findings": [f["id"] for f in related_findings],
    }


def _local_answer(question: str, docs: list, findings: list) -> str:
    if not docs:
        return (
            "I couldn't find a specific remediation guide for your question. "
            "Please consult your cloud provider's security documentation or "
            "review the CIS Benchmarks for your provider."
        )

    parts = [f"Based on your question, here are the most relevant remediation steps:\n"]
    for doc in docs[:2]:
        parts.append(f"**{doc['title']}**")
        for step in doc["steps"]:
            parts.append(f"  {step}")
        if doc.get("references"):
            parts.append(f"  Reference: {doc['references'][0]}")
        parts.append("")

    if findings:
        parts.append(f"*Related active findings: {', '.join(f['id'] for f in findings[:3])}*")

    return "\n".join(parts)


def _ask_openai(question: str, docs: list, findings: list, config: dict) -> str:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=config["rag"]["openai_api_key"])

        context = "\n\n".join(
            f"Guide: {d['title']}\nSteps:\n" + "\n".join(d["steps"])
            for d in docs
        )
        findings_ctx = "\n".join(f"- {f['title']} ({f['severity']})" for f in findings[:5])

        system_prompt = (
            "You are CloudGuard AI, an expert cloud security assistant. "
            "Answer questions about cloud misconfigurations and provide specific remediation steps. "
            "Be concise, accurate, and practical. Use the provided context documents and active findings."
        )
        user_prompt = f"""Context from knowledge base:
{context}

Active security findings:
{findings_ctx or 'None'}

User question: {question}"""

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=800,
            temperature=0.2,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.warning(f"OpenAI call failed: {e}. Falling back to local answer.")
        return _local_answer(question, docs, findings)


def _find_related_findings(question: str, findings: list) -> list:
    q = question.lower()
    related = []
    for f in findings:
        text = f"{f.get('title', '')} {f.get('service', '')} {f.get('description', '')}".lower()
        if any(word in text for word in q.split() if len(word) > 3):
            related.append(f)
    return related[:5]
