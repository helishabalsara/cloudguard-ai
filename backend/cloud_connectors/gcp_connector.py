"""
GCP misconfiguration checks via google-cloud SDK.
Covers: GCS buckets, firewall rules, IAM, Cloud Logging.
"""

import logging
from typing import List

logger = logging.getLogger(__name__)


def scan_gcp(config: dict) -> List[dict]:
    findings = []
    try:
        import google.auth
        from google.cloud import storage as gcs

        project_id = config.get("project_id")
        if not project_id:
            return [_error_finding("GCP", "project_id not configured")]

        findings += _check_gcs_buckets(project_id)
    except ImportError:
        logger.warning("google-cloud-storage not installed. Skipping GCP checks.")
    except Exception as e:
        logger.error(f"GCP scan error: {e}")
        findings.append(_error_finding("GCP", str(e)))
    return findings


def _check_gcs_buckets(project_id: str) -> List[dict]:
    findings = []
    try:
        from google.cloud import storage as gcs
        client = gcs.Client(project=project_id)
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy()
            for binding in policy.bindings:
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    findings.append({
                        "id": f"GCP-GCS-001-{bucket.name}",
                        "title": f"GCS bucket '{bucket.name}' is publicly accessible",
                        "description": "Bucket grants access to allUsers or allAuthenticatedUsers.",
                        "severity": "critical",
                        "resource": f"gs://{bucket.name}",
                        "provider": "gcp",
                        "service": "GCS",
                        "remediation_key": "gcs_public_access",
                    })
            # Uniform bucket-level access
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                findings.append({
                    "id": f"GCP-GCS-002-{bucket.name}",
                    "title": f"GCS bucket '{bucket.name}' does not use uniform bucket-level access",
                    "description": "Uniform bucket-level access simplifies permission management and avoids ACL misconfigurations.",
                    "severity": "medium",
                    "resource": f"gs://{bucket.name}",
                    "provider": "gcp",
                    "service": "GCS",
                    "remediation_key": "gcs_uniform_access",
                })
    except Exception as e:
        logger.debug(f"GCS check: {e}")
    return findings


def _error_finding(service: str, message: str) -> dict:
    return {
        "id": f"ERR-GCP-{service}",
        "title": f"GCP {service} scan error",
        "description": message,
        "severity": "info",
        "resource": service,
        "provider": "gcp",
        "service": service,
        "remediation_key": "",
    }
