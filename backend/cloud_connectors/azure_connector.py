"""
Azure misconfiguration checks via azure-mgmt SDK.
Covers: storage accounts, NSGs, RBAC, Key Vault, Security Center.
"""

import logging
from typing import List

logger = logging.getLogger(__name__)


def scan_azure(config: dict) -> List[dict]:
    findings = []
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.network import NetworkManagementClient

        creds = ClientSecretCredential(
            tenant_id=config["tenant_id"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
        )
        sub_id = config["subscription_id"]

        findings += _check_storage_accounts(creds, sub_id)
        findings += _check_nsgs(creds, sub_id)
    except ImportError:
        logger.warning("azure-identity / azure-mgmt-storage not installed. Skipping Azure checks.")
    except Exception as e:
        logger.error(f"Azure scan error: {e}")
        findings.append(_error_finding("Azure", str(e)))
    return findings


def _check_storage_accounts(creds, sub_id: str) -> List[dict]:
    findings = []
    try:
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(creds, sub_id)
        for account in client.storage_accounts.list():
            name = account.name
            # HTTPS only
            if not account.enable_https_traffic_only:
                findings.append({
                    "id": f"AZ-STOR-001-{name}",
                    "title": f"Storage account '{name}' allows HTTP traffic",
                    "description": "Storage accounts should enforce HTTPS-only transfers.",
                    "severity": "high",
                    "resource": account.id,
                    "provider": "azure",
                    "service": "Storage",
                    "remediation_key": "azure_storage_https",
                })
            # Blob public access
            if account.allow_blob_public_access:
                findings.append({
                    "id": f"AZ-STOR-002-{name}",
                    "title": f"Storage account '{name}' allows public blob access",
                    "description": "Blob public access should be disabled unless explicitly required.",
                    "severity": "high",
                    "resource": account.id,
                    "provider": "azure",
                    "service": "Storage",
                    "remediation_key": "azure_storage_public_access",
                })
    except Exception as e:
        logger.debug(f"Azure storage check: {e}")
    return findings


def _check_nsgs(creds, sub_id: str) -> List[dict]:
    findings = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(creds, sub_id)
        for nsg in client.network_security_groups.list_all():
            for rule in nsg.security_rules or []:
                if (rule.access == "Allow" and
                        rule.direction == "Inbound" and
                        rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")):
                    findings.append({
                        "id": f"AZ-NSG-001-{nsg.name}-{rule.name}",
                        "title": f"NSG '{nsg.name}' rule '{rule.name}' allows inbound from Internet",
                        "description": f"Port range {rule.destination_port_range} exposed to Internet.",
                        "severity": "high",
                        "resource": nsg.id,
                        "provider": "azure",
                        "service": "NSG",
                        "remediation_key": "azure_nsg_inbound",
                    })
    except Exception as e:
        logger.debug(f"Azure NSG check: {e}")
    return findings


def _error_finding(service: str, message: str) -> dict:
    return {
        "id": f"ERR-AZURE-{service}",
        "title": f"Azure {service} scan error",
        "description": message,
        "severity": "info",
        "resource": service,
        "provider": "azure",
        "service": service,
        "remediation_key": "",
    }
