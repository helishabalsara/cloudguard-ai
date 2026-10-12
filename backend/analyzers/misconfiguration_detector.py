"""
Orchestrates all cloud connector scans and aggregates findings.
"""

import logging
from typing import Dict, List

from backend.cloud_connectors.aws_connector import scan_aws
from backend.cloud_connectors.azure_connector import scan_azure
from backend.cloud_connectors.gcp_connector import scan_gcp
from backend.analyzers.risk_scorer import score_findings

logger = logging.getLogger(__name__)


def run_scan(provider: str, config: dict) -> Dict:
    """Run a full scan for the given provider and return structured results."""
    if provider == "aws":
        findings = scan_aws(config.get("aws", {}))
    elif provider == "azure":
        findings = scan_azure(config.get("azure", {}))
    elif provider == "gcp":
        findings = scan_gcp(config.get("gcp", {}))
    elif provider == "all":
        findings = (
            scan_aws(config.get("aws", {})) +
            scan_azure(config.get("azure", {})) +
            scan_gcp(config.get("gcp", {}))
        )
    else:
        return {"error": f"Unknown provider: {provider}", "findings": []}

    risk = score_findings(findings)
    return {
        "provider": provider,
        "findings": findings,
        "total": len(findings),
        "risk_score": risk["score"],
        "grade": risk["grade"],
        "breakdown": risk["breakdown"],
    }


def get_mock_findings() -> Dict:
    """Return realistic mock findings for demo/testing."""
    findings = [
        {
            "id": "S3-001-my-data-bucket",
            "title": "S3 bucket 'my-data-bucket' may allow public access",
            "description": "S3 Block Public Access is not fully enabled on this bucket.",
            "severity": "high",
            "resource": "arn:aws:s3:::my-data-bucket",
            "provider": "aws",
            "service": "S3",
            "remediation_key": "s3_public_access",
        },
        {
            "id": "CT-001",
            "title": "No CloudTrail trails configured",
            "description": "CloudTrail is not enabled. All API activity is unlogged.",
            "severity": "critical",
            "resource": "AWS Account",
            "provider": "aws",
            "service": "CloudTrail",
            "remediation_key": "cloudtrail_enable",
        },
        {
            "id": "IAM-001-admin-user",
            "title": "IAM user 'admin-user' has no MFA device",
            "description": "MFA should be enabled for all IAM users with console access.",
            "severity": "high",
            "resource": "arn:aws:iam::123456789012:user/admin-user",
            "provider": "aws",
            "service": "IAM",
            "remediation_key": "iam_mfa",
        },
        {
            "id": "SG-001-sg-0123456-22",
            "title": "Security group 'default' allows inbound from 0.0.0.0/0 on port 22",
            "description": "Unrestricted SSH access exposes the instance to brute-force attacks.",
            "severity": "high",
            "resource": "sg-0123456",
            "provider": "aws",
            "service": "EC2",
            "remediation_key": "sg_open_inbound",
        },
        {
            "id": "S3-003-logs-bucket",
            "title": "S3 bucket 'logs-bucket' is not encrypted",
            "description": "Server-side encryption is not enabled.",
            "severity": "medium",
            "resource": "arn:aws:s3:::logs-bucket",
            "provider": "aws",
            "service": "S3",
            "remediation_key": "s3_encryption",
        },
    ]
    risk = score_findings(findings)
    return {
        "provider": "aws (mock)",
        "findings": findings,
        "total": len(findings),
        "risk_score": risk["score"],
        "grade": risk["grade"],
        "breakdown": risk["breakdown"],
    }
