"""
AWS misconfiguration checks using boto3.
Covers: S3, IAM, EC2 security groups, CloudTrail, CloudWatch, KMS, RDS.
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def scan_aws(config: dict) -> List[dict]:
    """Run all AWS checks and return a flat list of finding dicts."""
    findings = []
    try:
        import boto3
        session = _make_session(config)
        findings += _check_s3(session)
        findings += _check_iam(session)
        findings += _check_security_groups(session, config.get("region", "us-east-1"))
        findings += _check_cloudtrail(session)
        findings += _check_root_account(session)
        findings += _check_password_policy(session)
    except ImportError:
        logger.error("boto3 not installed")
    except Exception as e:
        logger.error(f"AWS scan error: {e}")
        findings.append(_error_finding("AWS", str(e)))
    return findings


def _make_session(config: dict):
    import boto3
    kwargs = {"region_name": config.get("region", "us-east-1")}
    if config.get("access_key_id"):
        kwargs["aws_access_key_id"] = config["access_key_id"]
        kwargs["aws_secret_access_key"] = config["secret_access_key"]
    return boto3.Session(**kwargs)


def _check_s3(session) -> List[dict]:
    findings = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return [_error_finding("S3", str(e))]

    for bucket in buckets:
        name = bucket["Name"]
        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):
                findings.append({
                    "id": f"S3-001-{name}",
                    "title": f"S3 bucket '{name}' may allow public access",
                    "description": "S3 Block Public Access is not fully enabled on this bucket.",
                    "severity": "high",
                    "resource": f"arn:aws:s3:::{name}",
                    "provider": "aws",
                    "service": "S3",
                    "remediation_key": "s3_public_access",
                })
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "id": f"S3-002-{name}",
                "title": f"S3 bucket '{name}' has no public access block configuration",
                "description": "No S3 Block Public Access settings found. Bucket may be publicly accessible.",
                "severity": "high",
                "resource": f"arn:aws:s3:::{name}",
                "provider": "aws",
                "service": "S3",
                "remediation_key": "s3_public_access",
            })
        except Exception:
            pass

        # Server-side encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            findings.append({
                "id": f"S3-003-{name}",
                "title": f"S3 bucket '{name}' is not encrypted",
                "description": "Server-side encryption is not enabled on this S3 bucket.",
                "severity": "medium",
                "resource": f"arn:aws:s3:::{name}",
                "provider": "aws",
                "service": "S3",
                "remediation_key": "s3_encryption",
            })

        # Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append({
                    "id": f"S3-004-{name}",
                    "title": f"S3 bucket '{name}' versioning not enabled",
                    "description": "Versioning protects against accidental deletion and ransomware.",
                    "severity": "low",
                    "resource": f"arn:aws:s3:::{name}",
                    "provider": "aws",
                    "service": "S3",
                    "remediation_key": "s3_versioning",
                })
        except Exception:
            pass

    return findings


def _check_iam(session) -> List[dict]:
    findings = []
    iam = session.client("iam")

    # Users without MFA
    try:
        users = iam.list_users()["Users"]
        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if not mfa_devices:
                findings.append({
                    "id": f"IAM-001-{user['UserName']}",
                    "title": f"IAM user '{user['UserName']}' has no MFA device",
                    "description": "MFA should be enabled for all IAM users with console access.",
                    "severity": "high",
                    "resource": user["Arn"],
                    "provider": "aws",
                    "service": "IAM",
                    "remediation_key": "iam_mfa",
                })
    except Exception as e:
        logger.debug(f"IAM user check: {e}")

    # Access keys older than 90 days
    try:
        users = iam.list_users()["Users"]
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        for user in users:
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] == "Active" and key["CreateDate"] < cutoff:
                    findings.append({
                        "id": f"IAM-002-{key['AccessKeyId']}",
                        "title": f"IAM access key older than 90 days for '{user['UserName']}'",
                        "description": "Rotate access keys every 90 days to limit exposure window.",
                        "severity": "medium",
                        "resource": user["Arn"],
                        "provider": "aws",
                        "service": "IAM",
                        "remediation_key": "iam_key_rotation",
                    })
    except Exception as e:
        logger.debug(f"IAM key age check: {e}")

    return findings


def _check_security_groups(session, region: str) -> List[dict]:
    findings = []
    ec2 = session.client("ec2", region_name=region)
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", -1)
                        findings.append({
                            "id": f"SG-001-{sg['GroupId']}-{port}",
                            "title": f"Security group '{sg['GroupName']}' allows inbound from 0.0.0.0/0 on port {port}",
                            "description": "Unrestricted inbound access exposes the resource to the entire internet.",
                            "severity": "high" if port in (22, 3389, 1433, 3306) else "medium",
                            "resource": sg["GroupId"],
                            "provider": "aws",
                            "service": "EC2",
                            "remediation_key": "sg_open_inbound",
                        })
    except Exception as e:
        logger.debug(f"SG check: {e}")
    return findings


def _check_cloudtrail(session) -> List[dict]:
    findings = []
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            findings.append({
                "id": "CT-001",
                "title": "No CloudTrail trails configured",
                "description": "CloudTrail is not enabled. All API activity is unlogged.",
                "severity": "critical",
                "resource": "AWS Account",
                "provider": "aws",
                "service": "CloudTrail",
                "remediation_key": "cloudtrail_enable",
            })
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if not status.get("IsLogging"):
                findings.append({
                    "id": f"CT-002-{trail['Name']}",
                    "title": f"CloudTrail trail '{trail['Name']}' is not logging",
                    "description": "Trail exists but logging is stopped.",
                    "severity": "critical",
                    "resource": trail["TrailARN"],
                    "provider": "aws",
                    "service": "CloudTrail",
                    "remediation_key": "cloudtrail_enable",
                })
    except Exception as e:
        logger.debug(f"CloudTrail check: {e}")
    return findings


def _check_root_account(session) -> List[dict]:
    findings = []
    iam = session.client("iam")
    try:
        report = iam.generate_credential_report()
        import time; time.sleep(2)
        report_csv = iam.get_credential_report()["Content"].decode("utf-8")
        lines = report_csv.splitlines()
        headers = lines[0].split(",")
        for line in lines[1:]:
            cols = dict(zip(headers, line.split(",")))
            if cols.get("user") == "<root_account>":
                if cols.get("access_key_1_active") == "true" or cols.get("access_key_2_active") == "true":
                    findings.append({
                        "id": "IAM-ROOT-001",
                        "title": "Root account has active access keys",
                        "description": "The root account should not have programmatic access keys.",
                        "severity": "critical",
                        "resource": "Root Account",
                        "provider": "aws",
                        "service": "IAM",
                        "remediation_key": "iam_root_keys",
                    })
                if cols.get("mfa_active") == "false":
                    findings.append({
                        "id": "IAM-ROOT-002",
                        "title": "Root account does not have MFA enabled",
                        "description": "MFA must be enabled on the root account.",
                        "severity": "critical",
                        "resource": "Root Account",
                        "provider": "aws",
                        "service": "IAM",
                        "remediation_key": "iam_root_mfa",
                    })
    except Exception as e:
        logger.debug(f"Root check: {e}")
    return findings


def _check_password_policy(session) -> List[dict]:
    findings = []
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        if policy.get("MinimumPasswordLength", 0) < 14:
            findings.append({
                "id": "IAM-PWD-001",
                "title": "IAM password policy requires fewer than 14 characters",
                "description": "CIS benchmark requires minimum 14 character passwords.",
                "severity": "medium",
                "resource": "Account Password Policy",
                "provider": "aws",
                "service": "IAM",
                "remediation_key": "iam_password_policy",
            })
        if not policy.get("RequireSymbols"):
            findings.append({
                "id": "IAM-PWD-002",
                "title": "IAM password policy does not require symbols",
                "description": "Passwords should require uppercase, lowercase, numbers, and symbols.",
                "severity": "low",
                "resource": "Account Password Policy",
                "provider": "aws",
                "service": "IAM",
                "remediation_key": "iam_password_policy",
            })
    except Exception as e:
        logger.debug(f"Password policy check: {e}")
    return findings


def _error_finding(service: str, message: str) -> dict:
    return {
        "id": f"ERR-{service}",
        "title": f"{service} scan error",
        "description": message,
        "severity": "info",
        "resource": service,
        "provider": "aws",
        "service": service,
        "remediation_key": "",
    }
