"""
Remediation knowledge base — maps remediation_key to step-by-step fix guides.
This acts as the local RAG document store.
"""

REMEDIATION_GUIDES = {
    "s3_public_access": {
        "title": "Block S3 Bucket Public Access",
        "steps": [
            "1. Open AWS Console → S3 → select the bucket.",
            "2. Click 'Permissions' tab → 'Block public access (bucket settings)'.",
            "3. Click 'Edit' and enable all four Block Public Access settings.",
            "4. Click 'Save changes' and confirm.",
            "CLI: aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ],
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
    },
    "s3_encryption": {
        "title": "Enable S3 Server-Side Encryption",
        "steps": [
            "1. Open AWS Console → S3 → select the bucket.",
            "2. Click 'Properties' tab → 'Default encryption'.",
            "3. Select 'SSE-S3' (AES-256) or 'SSE-KMS' for stronger control.",
            "4. Save settings.",
            "CLI: aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
        ],
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"],
    },
    "s3_versioning": {
        "title": "Enable S3 Bucket Versioning",
        "steps": [
            "1. Open AWS Console → S3 → select the bucket.",
            "2. Click 'Properties' tab → 'Bucket Versioning'.",
            "3. Click 'Edit', select 'Enable', and save.",
            "CLI: aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled",
        ],
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"],
    },
    "iam_mfa": {
        "title": "Enable MFA for IAM Users",
        "steps": [
            "1. Open AWS Console → IAM → Users → select the user.",
            "2. Click 'Security credentials' tab → 'Assign MFA device'.",
            "3. Choose 'Authenticator app' and follow the setup wizard.",
            "4. Scan the QR code with Google Authenticator / Authy.",
            "5. Enter two consecutive TOTP codes and click 'Add MFA'.",
            "Enforce MFA: attach an IAM policy that denies all actions unless MFA is present.",
        ],
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"],
    },
    "iam_key_rotation": {
        "title": "Rotate IAM Access Keys",
        "steps": [
            "1. Create a new access key: aws iam create-access-key --user-name USERNAME",
            "2. Update all applications/scripts to use the new key.",
            "3. Test that the new key works.",
            "4. Deactivate the old key: aws iam update-access-key --access-key-id OLD_KEY_ID --status Inactive --user-name USERNAME",
            "5. After confirming nothing is broken, delete the old key: aws iam delete-access-key --access-key-id OLD_KEY_ID --user-name USERNAME",
        ],
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
    },
    "iam_root_keys": {
        "title": "Remove Root Account Access Keys",
        "steps": [
            "1. Log in to AWS Console with root credentials.",
            "2. Click your account name → 'Security credentials'.",
            "3. Under 'Access keys', delete all root access keys.",
            "4. Use IAM users/roles with least-privilege for all programmatic access.",
        ],
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"],
    },
    "iam_root_mfa": {
        "title": "Enable MFA on Root Account",
        "steps": [
            "1. Log in as root → click account name → 'Security credentials'.",
            "2. Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'.",
            "3. Choose a hardware MFA or authenticator app and follow setup.",
            "4. Store the MFA device securely — losing it locks you out of root.",
        ],
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"],
    },
    "sg_open_inbound": {
        "title": "Restrict Security Group Inbound Rules",
        "steps": [
            "1. Open AWS Console → EC2 → Security Groups → select the group.",
            "2. Click 'Inbound rules' → 'Edit inbound rules'.",
            "3. Change '0.0.0.0/0' to your specific IP range or VPC CIDR.",
            "4. For SSH (22) and RDP (3389): restrict to known admin IPs only.",
            "5. Delete any rules that are not required.",
            "CLI: aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0",
        ],
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"],
    },
    "cloudtrail_enable": {
        "title": "Enable AWS CloudTrail",
        "steps": [
            "1. Open AWS Console → CloudTrail → 'Create trail'.",
            "2. Enter a trail name and select 'Apply trail to all regions'.",
            "3. Under 'Storage location', create or select an S3 bucket for log storage.",
            "4. Enable log file validation for integrity assurance.",
            "5. Enable CloudWatch Logs integration for real-time alerting.",
            "CLI: aws cloudtrail create-trail --name my-trail --s3-bucket-name my-trail-bucket --is-multi-region-trail",
            "     aws cloudtrail start-logging --name my-trail",
        ],
        "references": ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"],
    },
    "iam_password_policy": {
        "title": "Strengthen IAM Account Password Policy",
        "steps": [
            "1. Open AWS Console → IAM → 'Account settings'.",
            "2. Under 'Password policy', click 'Edit'.",
            "3. Set: minimum length 14, require uppercase, lowercase, numbers, symbols.",
            "4. Enable 'Prevent password reuse' (last 24 passwords).",
            "5. Set password expiration to 90 days.",
            "CLI: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90",
        ],
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"],
    },
    "azure_storage_https": {
        "title": "Enforce HTTPS-Only on Azure Storage Account",
        "steps": [
            "1. Open Azure Portal → Storage Accounts → select the account.",
            "2. Under 'Settings', click 'Configuration'.",
            "3. Set 'Secure transfer required' to Enabled.",
            "4. Click Save.",
            "CLI: az storage account update --name ACCOUNT --resource-group RG --https-only true",
        ],
        "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"],
    },
    "gcs_public_access": {
        "title": "Remove Public Access from GCS Bucket",
        "steps": [
            "1. Open Google Cloud Console → Cloud Storage → select the bucket.",
            "2. Click 'Permissions' tab.",
            "3. Find and remove bindings for 'allUsers' and 'allAuthenticatedUsers'.",
            "4. Enable 'Prevent public access' in bucket settings.",
            "CLI: gsutil iam ch -d allUsers gs://BUCKET_NAME",
        ],
        "references": ["https://cloud.google.com/storage/docs/access-control/making-data-public"],
    },
}


def get_remediation(key: str) -> dict:
    return REMEDIATION_GUIDES.get(key, {
        "title": "No specific guide available",
        "steps": ["Consult the provider's security best practices documentation."],
        "references": [],
    })


def search_knowledge_base(query: str) -> list:
    """Simple keyword search over remediation guides."""
    query_lower = query.lower()
    results = []
    for key, guide in REMEDIATION_GUIDES.items():
        score = sum(
            1 for word in query_lower.split()
            if word in guide["title"].lower() or any(word in step.lower() for step in guide["steps"])
        )
        if score > 0:
            results.append({"key": key, "score": score, "guide": guide})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:3]
