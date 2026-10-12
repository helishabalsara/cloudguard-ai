"""
Remediation knowledge base with vector-embedded RAG retrieval.
Uses sentence-transformers for local embeddings + chromadb as the vector store.
Falls back to keyword search if chromadb/sentence-transformers are not installed.
"""

import logging
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Remediation documents — each is one retrieval unit
# ---------------------------------------------------------------------------
REMEDIATION_DOCS = [
    {
        "id": "s3_public_access",
        "title": "Block S3 Bucket Public Access",
        "content": """
S3 Block Public Access prevents buckets and objects from being publicly accessible.
Enable all four settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.
Steps:
1. AWS Console → S3 → bucket → Permissions tab → Block public access → Edit → enable all → Save.
2. CLI: aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
3. Audit all buckets: aws s3api list-buckets --query 'Buckets[*].Name' | xargs -I{} aws s3api get-public-access-block --bucket {}
Risk: public S3 buckets can expose sensitive data and are a common cause of breaches.
Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
""",
    },
    {
        "id": "s3_encryption",
        "title": "Enable S3 Default Encryption (SSE)",
        "content": """
S3 server-side encryption (SSE) encrypts objects at rest. Two options:
- SSE-S3 (AES-256): AWS-managed keys, free.
- SSE-KMS: Customer-managed KMS keys, audit trail via CloudTrail.
Steps:
1. Console → S3 → bucket → Properties → Default encryption → Edit → SSE-S3 or SSE-KMS → Save.
2. CLI: aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
3. Enforce in bucket policy: deny PutObject without SSE header.
Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
""",
    },
    {
        "id": "s3_versioning",
        "title": "Enable S3 Bucket Versioning",
        "content": """
S3 versioning keeps multiple versions of objects, protecting against accidental deletion and ransomware.
Steps:
1. Console → S3 → bucket → Properties → Bucket Versioning → Edit → Enable → Save.
2. CLI: aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled
3. Add a lifecycle rule to expire old versions after 90 days to control costs.
Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
""",
    },
    {
        "id": "iam_mfa",
        "title": "Enable MFA for IAM Users",
        "content": """
Multi-factor authentication (MFA) adds a second layer of identity verification.
Without MFA, a leaked password alone grants full account access.
Steps:
1. Console → IAM → Users → select user → Security credentials → Assign MFA device.
2. Choose Virtual MFA (TOTP). Scan QR with Google Authenticator or Authy.
3. Enter two consecutive TOTP codes → Add MFA.
4. Enforce: attach IAM policy denying all actions unless aws:MultiFactorAuthPresent=true.
   Policy snippet:
   {"Effect":"Deny","NotAction":["iam:CreateVirtualMFADevice","iam:EnableMFADevice"],"Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}
5. CLI to list users without MFA: aws iam list-users | jq '.Users[].UserName' | xargs -I{} aws iam list-mfa-devices --user-name {}
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html
""",
    },
    {
        "id": "iam_key_rotation",
        "title": "Rotate IAM Access Keys (90-day policy)",
        "content": """
Access keys that are never rotated are a persistent credential exposure risk.
AWS recommends rotating every 90 days or using IAM roles instead of long-term keys.
Steps:
1. Create new key: aws iam create-access-key --user-name USERNAME
2. Update all apps/scripts/CI with the new key.
3. Test: aws sts get-caller-identity (with new key)
4. Deactivate old key: aws iam update-access-key --access-key-id OLD_ID --status Inactive --user-name USERNAME
5. Monitor for 24h, then delete: aws iam delete-access-key --access-key-id OLD_ID --user-name USERNAME
Best practice: replace long-term keys with IAM roles + instance profiles or OIDC federation.
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
""",
    },
    {
        "id": "iam_root_keys",
        "title": "Delete Root Account Access Keys",
        "content": """
The root account has unrestricted access to all AWS services. Programmatic root access keys are extremely dangerous.
Steps:
1. Log in as root → account name → Security credentials → Access keys.
2. Delete ALL root access keys (there should be none).
3. Create IAM users/roles with least-privilege for all automation.
4. Enable root account MFA immediately after removing keys.
5. Use AWS Organizations SCPs to restrict root actions across member accounts.
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials
""",
    },
    {
        "id": "iam_root_mfa",
        "title": "Enable MFA on the AWS Root Account",
        "content": """
The root account controls billing and all IAM policies. It must be protected with hardware MFA.
Steps:
1. Log in as root → click account name → Security credentials → MFA → Assign MFA device.
2. Prefer a hardware MFA key (YubiKey / physical TOTP device) over a virtual app.
3. Store the MFA device and backup codes in a physical safe.
4. If MFA device is lost, recovery requires contacting AWS Support with identity verification.
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html
""",
    },
    {
        "id": "sg_open_inbound",
        "title": "Restrict EC2 Security Group Inbound Rules (0.0.0.0/0)",
        "content": """
Security groups with 0.0.0.0/0 (any source) on sensitive ports expose instances to internet attacks.
Highest risk ports: 22 (SSH), 3389 (RDP), 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL).
Steps:
1. Console → EC2 → Security Groups → select group → Inbound rules → Edit.
2. Replace 0.0.0.0/0 with specific CIDR (your office IP, VPN range, or VPC CIDR).
3. For SSH/RDP admin access: use AWS Systems Manager Session Manager instead — no inbound port needed.
4. CLI remove: aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0
5. Audit all groups: aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0
Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html
""",
    },
    {
        "id": "cloudtrail_enable",
        "title": "Enable AWS CloudTrail for All Regions",
        "content": """
CloudTrail logs all API activity. Without it, there is no forensic trail for incident investigation.
Steps:
1. Console → CloudTrail → Create trail → name it → Apply to all regions.
2. Choose or create an S3 bucket for log storage. Enable log file validation (SHA-256 digest).
3. Enable CloudWatch Logs integration for real-time alerting.
4. Enable management events (read + write). Optionally enable data events for S3/Lambda.
5. CLI: aws cloudtrail create-trail --name main-trail --s3-bucket-name my-trail-logs --is-multi-region-trail
         aws cloudtrail start-logging --name main-trail
6. Protect the S3 bucket: enable MFA delete, block public access, encrypt with KMS.
Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
""",
    },
    {
        "id": "iam_password_policy",
        "title": "Harden IAM Account Password Policy (CIS Benchmark)",
        "content": """
A weak password policy allows short, simple passwords that are easy to brute-force.
CIS Benchmark requirements:
- Minimum length: 14 characters
- Require uppercase, lowercase, numbers, and symbols
- Password expiry: 90 days
- Prevent reuse: last 24 passwords
- Lock out after 3 failed attempts
Steps:
1. Console → IAM → Account settings → Edit password policy.
2. CLI: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
""",
    },
    {
        "id": "azure_storage_https",
        "title": "Enforce HTTPS-Only Transfers on Azure Storage Account",
        "content": """
Azure storage accounts accepting HTTP allow data interception in transit.
Steps:
1. Portal → Storage Accounts → account → Configuration → Secure transfer required → Enabled → Save.
2. CLI: az storage account update --name ACCOUNT --resource-group RG --https-only true
3. Verify: az storage account show --name ACCOUNT --query enableHttpsTrafficOnly
Reference: https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer
""",
    },
    {
        "id": "azure_storage_public_access",
        "title": "Disable Blob Public Access on Azure Storage",
        "content": """
Public blob access allows unauthenticated reads of any container marked public.
Steps:
1. Portal → Storage Accounts → account → Configuration → Blob public access → Disabled → Save.
2. CLI: az storage account update --name ACCOUNT --resource-group RG --allow-blob-public-access false
3. Audit containers: az storage container list --account-name ACCOUNT --query '[?properties.publicAccess!=null]'
Reference: https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure
""",
    },
    {
        "id": "azure_nsg_inbound",
        "title": "Restrict Azure NSG Inbound Rules from Internet",
        "content": """
NSG rules with source=Internet or 0.0.0.0/0 expose Azure resources to the public internet.
Steps:
1. Portal → Networking → NSG → Inbound rules → identify any Allow rule with source=Internet.
2. Change source to a specific IP range, VNet, or application security group.
3. For management (SSH/RDP): use Azure Bastion instead of opening ports.
4. CLI: az network nsg rule update --resource-group RG --nsg-name NSG_NAME --name RULE_NAME --source-address-prefixes 10.0.0.0/8
Reference: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
""",
    },
    {
        "id": "gcs_public_access",
        "title": "Remove Public Access from GCS Bucket",
        "content": """
GCS buckets granting access to allUsers or allAuthenticatedUsers are publicly readable/writable.
Steps:
1. Console → Cloud Storage → bucket → Permissions → find allUsers/allAuthenticatedUsers bindings → Remove.
2. Enable Uniform Bucket-Level Access to prevent per-object public ACLs.
3. CLI: gsutil iam ch -d allUsers gs://BUCKET_NAME
         gsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME
4. Set public access prevention: gcloud storage buckets update gs://BUCKET --public-access-prevention=enforced
Reference: https://cloud.google.com/storage/docs/access-control/making-data-public
""",
    },
    {
        "id": "gcs_uniform_access",
        "title": "Enable Uniform Bucket-Level Access on GCS",
        "content": """
Uniform bucket-level access disables per-object ACLs and enforces IAM-only access control.
Without it, misconfigured object ACLs can expose individual files even when bucket IAM looks correct.
Steps:
1. Console → Cloud Storage → bucket → Permissions → Access control → Uniform → Save.
2. CLI: gsutil uniformbucketlevelaccess set on gs://BUCKET_NAME
3. Verify: gsutil uniformbucketlevelaccess get gs://BUCKET_NAME
Reference: https://cloud.google.com/storage/docs/uniform-bucket-level-access
""",
    },
]


# ---------------------------------------------------------------------------
# Vector store — build once, reuse for all queries
# ---------------------------------------------------------------------------
_vector_store = None


def _build_vector_store():
    """Build a chromadb collection with sentence-transformer embeddings."""
    global _vector_store
    if _vector_store is not None:
        return _vector_store

    try:
        import chromadb
        from chromadb.utils import embedding_functions

        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        client = chromadb.Client()
        collection = client.get_or_create_collection(
            name="remediation_kb",
            embedding_function=ef,
            metadata={"hnsw:space": "cosine"},
        )

        if collection.count() == 0:
            collection.add(
                ids=[doc["id"] for doc in REMEDIATION_DOCS],
                documents=[doc["content"] for doc in REMEDIATION_DOCS],
                metadatas=[{"title": doc["title"], "id": doc["id"]} for doc in REMEDIATION_DOCS],
            )
            logger.info(f"RAG vector store built with {len(REMEDIATION_DOCS)} documents.")

        _vector_store = collection
        return collection

    except ImportError:
        logger.warning(
            "chromadb or sentence-transformers not installed. "
            "Install with: pip install chromadb sentence-transformers\n"
            "Falling back to keyword search."
        )
        return None


def semantic_search(query: str, n_results: int = 3) -> List[Dict]:
    """
    Retrieve the top-n most semantically relevant remediation guides for `query`.
    Uses vector similarity (cosine) via chromadb + sentence-transformers.
    Falls back to keyword BM25-lite if vector store unavailable.
    """
    collection = _build_vector_store()

    if collection is not None:
        results = collection.query(query_texts=[query], n_results=min(n_results, len(REMEDIATION_DOCS)))
        docs = []
        for i, doc_id in enumerate(results["ids"][0]):
            doc = next((d for d in REMEDIATION_DOCS if d["id"] == doc_id), None)
            if doc:
                docs.append({
                    "key": doc_id,
                    "score": 1 - results["distances"][0][i],  # cosine similarity
                    "guide": {"title": doc["title"], "content": doc["content"]},
                })
        return docs

    return _keyword_fallback(query, n_results)


def _keyword_fallback(query: str, n: int) -> List[Dict]:
    """BM25-lite keyword fallback when vector store is unavailable."""
    q_terms = set(query.lower().split())
    results = []
    for doc in REMEDIATION_DOCS:
        text = (doc["title"] + " " + doc["content"]).lower()
        score = sum(1 for t in q_terms if len(t) > 3 and t in text)
        if score > 0:
            results.append({"key": doc["id"], "score": score,
                             "guide": {"title": doc["title"], "content": doc["content"]}})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:n]


def get_remediation(key: str) -> dict:
    doc = next((d for d in REMEDIATION_DOCS if d["id"] == key), None)
    if not doc:
        return {"title": "No guide available", "content": "Consult your cloud provider's security documentation."}
    return {"title": doc["title"], "content": doc["content"]}


# Legacy alias used by remediation_engine
def search_knowledge_base(query: str) -> List[Dict]:
    return semantic_search(query)
