"""
Agentic RAG remediation engine.

Agent loop:
  1. Decompose the user question into sub-queries if complex
  2. Retrieve relevant docs via semantic search (chromadb + sentence-transformers)
  3. Retrieve related active findings
  4. Synthesise answer — via OpenAI LLM (if key provided) or structured local answer
  5. Suggest follow-up checks the user should run
"""

import logging
import re
from typing import Dict, List

from backend.rag.knowledge_base import semantic_search, get_remediation

logger = logging.getLogger(__name__)

# Maximum retrieval iterations the agent will run
MAX_AGENT_STEPS = 3


def ask(question: str, findings: List[dict], config: dict) -> Dict:
    """
    Agentic RAG: iteratively retrieves context and synthesises a grounded answer.
    """
    mode = config.get("rag", {}).get("mode", "local")
    openai_key = config.get("rag", {}).get("openai_api_key", "")

    # --- Step 1: Decompose complex questions ---
    sub_queries = _decompose_question(question)

    # --- Step 2: Multi-step retrieval over sub-queries ---
    all_docs = []
    seen_keys = set()
    for sub_q in sub_queries:
        results = semantic_search(sub_q, n_results=3)
        for r in results:
            if r["key"] not in seen_keys:
                all_docs.append(r)
                seen_keys.add(r["key"])
        if len(all_docs) >= MAX_AGENT_STEPS * 3:
            break

    # --- Step 3: Find related active findings ---
    related_findings = _find_related_findings(question, findings)

    # --- Step 4: Synthesise answer ---
    if mode == "openai" and openai_key:
        answer = _ask_openai(question, all_docs, related_findings, config)
    else:
        answer = _structured_local_answer(question, all_docs, related_findings)

    # --- Step 5: Suggest follow-up checks ---
    follow_ups = _suggest_follow_ups(all_docs, related_findings)

    return {
        "question": question,
        "answer": answer,
        "sources": [r["guide"]["title"] for r in all_docs[:3]],
        "related_findings": [f["id"] for f in related_findings],
        "follow_up_checks": follow_ups,
        "retrieval_steps": len(sub_queries),
    }


def _decompose_question(question: str) -> List[str]:
    """
    Break a complex question into focused sub-queries for multi-step retrieval.
    Keeps the original question and generates targeted variants.
    """
    q = question.lower()
    sub_queries = [question]

    # Extract service/resource mentions for targeted retrieval
    service_patterns = {
        "s3": ["s3 bucket public access", "s3 encryption", "s3 versioning"],
        "iam": ["iam mfa user", "iam access key rotation", "iam password policy"],
        "cloudtrail": ["cloudtrail logging enable"],
        "security group": ["security group inbound 0.0.0.0/0"],
        "root": ["root account mfa keys"],
        "azure storage": ["azure storage https blob public access"],
        "gcs": ["gcs bucket public access uniform"],
    }
    for keyword, extras in service_patterns.items():
        if keyword in q:
            sub_queries.extend(extras[:2])
            break

    return list(dict.fromkeys(sub_queries))[:MAX_AGENT_STEPS]


def _structured_local_answer(question: str, docs: List[dict], findings: List[dict]) -> str:
    if not docs:
        return (
            "I couldn't find a specific remediation guide for your question. "
            "Consult your cloud provider's security documentation or the CIS Benchmarks."
        )

    parts = ["Here are the most relevant remediation steps based on your question:\n"]
    for r in docs[:2]:
        guide = r["guide"]
        parts.append(f"**{guide['title']}**\n")
        # Show full content, trimmed to ~600 chars for readability
        content = guide.get("content", "").strip()
        parts.append(content[:800] + ("..." if len(content) > 800 else ""))
        parts.append("")

    if findings:
        parts.append(
            f"\n*Related active findings in your environment: "
            f"{', '.join(f['id'] for f in findings[:3])}*"
        )

    return "\n".join(parts)


def _ask_openai(question: str, docs: List[dict], findings: List[dict], config: dict) -> str:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=config["rag"]["openai_api_key"])

        context = "\n\n---\n\n".join(
            f"[{r['guide']['title']}]\n{r['guide'].get('content', '')[:600]}"
            for r in docs
        )
        findings_ctx = "\n".join(
            f"- [{f['severity'].upper()}] {f['title']} (resource: {f['resource']})"
            for f in findings[:5]
        ) or "No active findings."

        system_prompt = (
            "You are CloudGuard AI, an expert cloud security engineer. "
            "Answer questions about cloud misconfigurations and provide "
            "precise, actionable remediation steps with CLI commands where applicable. "
            "Ground your answer in the provided knowledge base documents. "
            "If the active findings are relevant, reference them specifically."
        )
        user_prompt = (
            f"Knowledge base context:\n{context}\n\n"
            f"Active security findings in the environment:\n{findings_ctx}\n\n"
            f"Question: {question}"
        )

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=900,
            temperature=0.15,
        )
        return response.choices[0].message.content

    except Exception as e:
        logger.warning(f"OpenAI call failed ({e}). Using local answer.")
        return _structured_local_answer(question, docs, findings)


def _find_related_findings(question: str, findings: List[dict]) -> List[dict]:
    q_terms = {w for w in question.lower().split() if len(w) > 3}
    related = []
    for f in findings:
        text = f"{f.get('title','')} {f.get('service','')} {f.get('description','')}".lower()
        if any(t in text for t in q_terms):
            related.append(f)
    return related[:5]


def _suggest_follow_ups(docs: List[dict], findings: List[dict]) -> List[str]:
    """Generate contextual follow-up checks based on retrieved docs."""
    suggestions = []
    titles = " ".join(r["guide"]["title"].lower() for r in docs)

    if "s3" in titles:
        suggestions.append("Run: aws s3api list-buckets | check each for public-access-block and encryption")
    if "iam" in titles or "mfa" in titles:
        suggestions.append("Run: aws iam generate-credential-report to audit all user credential states")
    if "cloudtrail" in titles:
        suggestions.append("Run: aws cloudtrail describe-trails to verify multi-region coverage")
    if "security group" in titles:
        suggestions.append("Run: aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0")
    if not suggestions and findings:
        suggestions.append(f"Investigate finding {findings[0]['id']}: {findings[0].get('title','')}")

    return suggestions[:3]
