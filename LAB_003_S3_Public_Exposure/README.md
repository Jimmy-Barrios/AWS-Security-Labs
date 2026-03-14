# LAB-003: S3 Public Exposure — Detecting and Fixing a Public S3 Bucket

|  |  |
| --- | --- |
| **Estimated cost** | < $0.10 per run |
| **Estimated time** | 45–60 minutes |
| **MITRE ATT&CK (Cloud)** | **T1530** — Data from Cloud Storage (Collection) |

---

## 1. Lab Overview

**Scenario:** A developer at a mid-size company needs to share quarterly financial reports with an external auditing firm. Instead of using a pre-signed URL or setting up a temporary access grant, they take the shortcut: turn off Block Public Access on an S3 bucket, slap a public-read bucket policy on it, drop in the files, and send the auditor the URL. "It's just for two weeks," they say. Six months later the bucket still exists, still has three directories of internal data in it, and nobody has thought about it since.

An attacker running a bucket name wordlist — or finding the name in a leaked email, a CloudFront distribution config, or an SSL certificate transparency log — hits the bucket with zero AWS credentials and walks out with everything in it. The company doesn't find out for weeks, because nobody was watching for anonymous S3 access.

This lab walks you through the full cycle: deploy the misconfigured bucket, simulate the attacker pulling data with `--no-sign-request`, find the anonymous access events in CloudTrail, and shut it down with Block Public Access and a policy delete.

---

## 2. Learning Objectives

When you're done you'll be able to:

- Explain why disabling Block Public Access combined with a public bucket policy creates a data exposure reachable by anyone on the internet without AWS credentials.
- Simulate an anonymous S3 data exfiltration attack using `--no-sign-request` and direct HTTP access.
- Use CloudWatch Logs Insights to find anonymous S3 access events (`GetObject`, `ListBucket`) in CloudTrail.
- Harden the bucket using Block Public Access and bucket policy removal, then confirm the attack is blocked with a 403.

---

## 3. Architecture

**Services used**

| Service | Role in this lab |
| --- | --- |
| **S3 (data bucket)** | The misconfigured bucket: Block Public Access disabled, public bucket policy allowing `s3:GetObject` and `s3:ListBucket`. Holds fake sensitive files. |
| **S3 (trail bucket)** | Private bucket for CloudTrail log file delivery. |
| **CloudTrail** | Trail with S3 data events enabled for the data bucket. Captures every `GetObject` and `ListBucket` call, including anonymous ones. |
| **CloudWatch Logs** | Log group for trail events. You query this with Logs Insights to find the anonymous access. |

**Data flow**

- **Attacker:** Uses `aws s3 ls --no-sign-request` and `aws s3 cp --no-sign-request` to list and download objects. No credentials. CloudTrail records these with `userIdentity.type = "Anonymous"`.
- **Defender:** Queries CloudWatch Logs Insights for `GetObject` and `ListBucket` events where `userIdentity.type = "Anonymous"`. Source IP and timestamps are in the log.
- **Hardened:** After Block Public Access is re-enabled and the bucket policy is removed, the same commands get a 403.

**Diagram (text)**

```
[ Internet / Attacker ]
         |
         |  aws s3 cp s3://BUCKET/config/app-config.json --no-sign-request
         |  curl https://BUCKET.s3.amazonaws.com/config/app-config.json
         |  (no AWS credentials required)
         v
[ S3 — lab-003-data bucket ]
  Block Public Access: DISABLED        <-- misconfiguration
  Bucket policy: Principal "*"         <-- misconfiguration
         |
         v
[ CloudTrail — S3 data events enabled ]
         |
    +----+----+
    v         v
[ S3 trail ] [ CloudWatch Logs ]
             (Logs Insights query)
```

---

## 4. The Misconfiguration

**What's wrong**

The data bucket has two settings working against it at the same time:

1. **Block Public Access is disabled.** AWS ships every new bucket with all four Block Public Access settings enabled by default. Someone turned them off — in the Console, or via a one-liner — to make it easier to add a public-read policy.
2. **The bucket policy grants `s3:GetObject` and `s3:ListBucket` to `Principal: "*"`.** That means everyone. No authentication, no signed request, no AWS account needed. Just an HTTP GET.

Together, these settings make every object in the bucket reachable via a plain URL. You can paste the URL into a browser.

**Why you still see this in real orgs**

AWS's own static website hosting docs used to walk through disabling Block Public Access and adding a public policy as the default flow. Dozens of still-active blog posts and Stack Overflow answers carry that same pattern. Teams copy it without understanding the risk, especially for buckets they intend to be "just for partners" or "just temporary." Content delivery, external report sharing, CI/CD artifact staging, partner data drops — all legitimate use cases that sometimes leave a permanently public bucket sitting around after the project ends.

**MITRE ATT&CK**

**T1530 — Data from Cloud Storage** (Collection). Adversaries access data objects from cloud storage. No credentials required when the bucket is misconfigured for public access. This is one of the most documented and most exploited patterns in AWS security history.

---

## 5. Lab Setup

### Prerequisites

- **AWS CLI v2** installed and configured with credentials that can create S3 buckets, IAM roles, a CloudTrail trail, and a CloudWatch Logs group.
- **Terraform 1.5+** installed.
- A sandbox AWS account where you're allowed to disable Block Public Access.

### Account-level Block Public Access — check this first

AWS has two layers of Block Public Access: **bucket-level** (which Terraform controls for the data bucket) and **account-level** (which can silently override the bucket level). Many AWS accounts — especially older ones or ones managed by an organization — have the account-level setting turned on. If it is, the public bucket policy won't take effect even after Terraform disables the bucket-level settings, and the attacker steps won't produce the expected results.

Check your account-level settings before deploying:

```bash
aws s3control get-public-access-block --account-id YOUR_ACCOUNT_ID
```

If `BlockPublicPolicy` or `RestrictPublicBuckets` is `true`, disable them for this lab:

```bash
aws s3control put-public-access-block \
  --account-id YOUR_ACCOUNT_ID \
  --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```

You will re-enable these in Section 10. Do not leave account-level Block Public Access disabled in a real production account.

### Authentication

If you use a named AWS profile, set it before running Terraform:

```bash
export AWS_PROFILE=my-lab
```

### Deploy the vulnerable environment

```bash
cd LAB_003_S3_Public_Exposure/terraform
terraform init
terraform plan
terraform apply -auto-approve
```

When apply finishes, note the outputs: `data_bucket_name`, `log_group_name`, `region`, and `account_id`. The bucket name is what you'll use for every attacker command in Section 6.

---

## 6. Attacker Perspective

The attacker's job here is straightforward: find the bucket, confirm it's open, and take everything in it. No AWS credentials, no assumed roles, no privilege escalation needed.

In the real world, attackers find bucket names through certificate transparency logs (SSL certs sometimes list bucket names as subject alternative names), leaked URLs in web app source code or JavaScript bundles, CloudFront distribution configs, error messages in app responses, or brute-force wordlists of common naming patterns like `company-name-reports`, `company-name-backups`, or `company-name-data`. For this lab you get the bucket name directly from `terraform output data_bucket_name`.

**Step 1: Confirm the bucket is accessible without credentials**

```bash
aws s3 ls s3://YOUR_BUCKET_NAME --no-sign-request
```

`--no-sign-request` tells the CLI to skip request signing entirely. If you get a listing back, the bucket is wide open. You should see the top-level prefixes: `config/`, `internal/`, and `reports/`.

**Step 2: List all objects recursively**

```bash
aws s3 ls s3://YOUR_BUCKET_NAME --recursive --no-sign-request
```

Full inventory in seconds. Any attacker looking at this output would go straight for `config/app-config.json`.

**Step 3: Download a sensitive file**

```bash
aws s3 cp s3://YOUR_BUCKET_NAME/config/app-config.json . --no-sign-request
cat app-config.json
```

The config file is on your machine. In a real incident, this file would contain a real database password or API key — exactly the kind of secret developers put in config files and then store in S3.

**Step 4: Exfiltrate the rest**

```bash
aws s3 cp s3://YOUR_BUCKET_NAME/reports/q4-financials.csv . --no-sign-request
aws s3 cp s3://YOUR_BUCKET_NAME/internal/employee-roster.csv . --no-sign-request
```

**Step 5: Try direct HTTP — no CLI required**

This is what makes S3 public exposure uniquely dangerous. You don't need the AWS CLI. You don't need any AWS tooling at all. Just curl:

```bash
curl -o app-config.json \
  "https://YOUR_BUCKET_NAME.s3.amazonaws.com/config/app-config.json"
```

Or paste the URL directly into a browser. Any HTTP client works. The attack surface isn't specific to AWS users.

CloudTrail recorded every one of those operations. The attacker's source IP is in the logs. Switch to the defender role.

---

## 7. Defender Perspective

Every `GetObject` and `ListBucket` call against the data bucket — authenticated or not — is recorded in CloudTrail because S3 data events are enabled for that bucket. Anonymous requests show up with `userIdentity.type = "Anonymous"`, which is exactly what you search for.

Wait 5–15 minutes after the attacker steps for events to propagate to CloudWatch Logs, then run the queries below.

**Find all anonymous S3 access**

1. Go to **CloudWatch** → **Logs** → **Log groups**.
2. Select the log group from your Terraform output (e.g. `/aws/cloudtrail/lab-003-cloudtrail-events`).
3. Click **Query with Logs Insights**.
4. Set the time range to cover when you ran the attacker commands.
5. Run:

```
fields @timestamp, eventName, userIdentity.type, sourceIPAddress, requestParameters.bucketName, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter userIdentity.type = "Anonymous"
| filter eventName in ["GetObject", "ListBucket"]
| sort @timestamp desc
```

You should see your `GetObject` and `ListBucket` events with `userIdentity.type = "Anonymous"`. The `sourceIPAddress` is your own IP — in a real incident that's the attacker's IP.

**Narrow to specific files accessed**

```
fields @timestamp, eventName, requestParameters.key, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter userIdentity.type = "Anonymous"
| filter eventName = "GetObject"
| filter requestParameters.bucketName = "YOUR_BUCKET_NAME"
| sort @timestamp desc
```

This tells you exactly which files were accessed and when — critical for a breach scope assessment.

**Count exfiltration events by source IP**

```
fields sourceIPAddress, eventName
| filter eventSource = "s3.amazonaws.com"
| filter userIdentity.type = "Anonymous"
| stats count(*) as eventCount by sourceIPAddress, eventName
| sort eventCount desc
```

If one IP pulled dozens of objects in a short window, that's an exfiltration pattern. A real SOC team would pivot on that IP.

**What the raw CloudTrail event looks like**

For anonymous access, the `userIdentity` block looks like this:

```json
{
  "userIdentity": {
    "type": "Anonymous",
    "principalId": "ANONYMOUS_PRINCIPAL"
  }
}
```

No account ID. No role. No user name. Just `Anonymous`. That field is your detection anchor — everything else (IP, timestamp, object key) builds the incident timeline from it.

**AWS Config and Security Hub**

If you have Security Hub enabled in your account, the public bucket will trigger two findings automatically:

- **S3.2** — S3 buckets should prohibit public read access
- **S3.3** — S3 buckets should prohibit public write access

AWS Config rule **`s3-bucket-public-read-prohibited`** will also flag the bucket. In a mature environment these findings surface before an attacker ever gets to the data. In this lab, we're doing it manually with Logs Insights to understand what's actually happening in the logs.

---

## 8. Harden & Verify

Two AWS CLI commands fix this: re-enable Block Public Access at the bucket level and delete the public bucket policy. No Terraform changes.

**Step 1: Re-enable Block Public Access on the bucket**

```bash
aws s3api put-public-access-block \
  --bucket YOUR_BUCKET_NAME \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

`RestrictPublicBuckets` alone would be enough to neutralize the public policy, but flipping all four ensures the bucket is fully locked down.

**Step 2: Delete the public bucket policy**

```bash
aws s3api delete-bucket-policy --bucket YOUR_BUCKET_NAME
```

The policy granting `s3:GetObject` and `s3:ListBucket` to `Principal: "*"` is gone. Even if Block Public Access were ever disabled again, there would be no public policy to take effect.

**Step 3: Re-run the attack to confirm it's blocked**

List the bucket:

```bash
aws s3 ls s3://YOUR_BUCKET_NAME --no-sign-request
```

Expected:

```
An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```

Download a file:

```bash
aws s3 cp s3://YOUR_BUCKET_NAME/config/app-config.json . --no-sign-request
```

Expected:

```
An error occurred (AccessDenied) when calling the GetObject operation: Access Denied
```

Check the HTTP endpoint directly:

```bash
curl -I "https://YOUR_BUCKET_NAME.s3.amazonaws.com/config/app-config.json"
```

Expected: `HTTP/1.1 403 Forbidden`

The bucket is no longer publicly accessible.

**If you prefer the Console**

1. Go to **S3** → select the `lab-003-data-...` bucket.
2. Click the **Permissions** tab.
3. Under **Block public access (bucket settings)**, click **Edit**, enable all four checkboxes, click **Save changes**.
4. Under **Bucket policy**, click **Delete** and confirm.
5. Re-run the `--no-sign-request` commands above to verify.

---

## 9. Why It Matters

**Real-world breaches**

Public S3 buckets have been directly responsible for some of the most publicized data exposures in cloud history. Accenture (2017), Verizon (2017), the Republican National Committee (2017), Booz Allen Hamilton (2017), and GoDaddy (2019) all had sensitive data — customer records, internal credentials, classified reports — sitting in publicly readable S3 buckets for weeks or months before anyone noticed. The pattern is identical in every case: someone made an exception to share something quickly, and nobody cleaned it up or monitored for unexpected access.

The average time-to-discovery for a public S3 exposure is measured in weeks. In that window, the data has usually already been scraped by automated scanners that crawl for open buckets continuously.

**Why this keeps happening**

Block Public Access was introduced by AWS in 2018 specifically to stop this class of misconfiguration. Account-level Block Public Access (available since 2019) means you can prevent any bucket in the account from ever becoming public, regardless of bucket-level settings. AWS Organizations SCPs can enforce it across every account in a company. These controls exist and work. The problem is that not everyone enables them, and legacy buckets created before these controls existed often slip through.

**Compliance impact**

A single publicly accessible bucket containing employee records, financial data, or configuration files can trigger GDPR breach notification requirements (72-hour window from discovery), CCPA penalties, and findings in SOC 2 and PCI-DSS audits. The regulatory and reputational cost often dwarfs the technical remediation effort.

Enable Block Public Access at the account level. Enforce it with an SCP. Run `s3-bucket-public-read-prohibited` as an AWS Config rule. These are one-time setup tasks that permanently close this attack surface.

---

## 10. Teardown

### Re-enable account-level Block Public Access (if you disabled it in Section 5)

```bash
aws s3control put-public-access-block \
  --account-id YOUR_ACCOUNT_ID \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

Verify it's back:

```bash
aws s3control get-public-access-block --account-id YOUR_ACCOUNT_ID
```

All four values should be `true`.

### Destroy Terraform resources

```bash
terraform destroy -auto-approve
```

Both S3 buckets have `force_destroy = true`, so Terraform will delete them even if they still contain objects. The CloudTrail trail, CloudWatch log group, and IAM role are all removed as well.

### Verify cleanup

- Data bucket is gone: `aws s3 ls s3://YOUR_BUCKET_NAME` should return `NoSuchBucket`.
- Trail is gone: `aws cloudtrail describe-trails --region us-east-1` should not list `lab-003-audit-trail`.
- Log group is gone: `aws logs describe-log-groups --log-group-name-prefix lab-003` should return empty.
- IAM role is gone: `aws iam get-role --role-name Lab003CloudTrailCloudWatchRole` should return a `NoSuchEntity` error.

---

## Summary

| Section | What it covers |
| --- | --- |
| 1–2 | Scenario (public S3 = unauthenticated data access) and learning objectives. |
| 3–4 | Architecture (S3, CloudTrail, CloudWatch), data flow, and the misconfiguration (Block Public Access disabled + public bucket policy) + MITRE T1530. |
| 5 | Terraform: CloudTrail with S3 data events, the vulnerable public bucket, fake sensitive files. Account-level Block Public Access check. |
| 6 | Attacker: list and download files with `--no-sign-request` and plain HTTP — no AWS credentials needed at any step. |
| 7 | Defender: CloudWatch Logs Insights queries for `Anonymous` access events. Security Hub and Config coverage. |
| 8 | Harden via CLI: Block Public Access + delete bucket policy. Re-run attack. Confirm 403. |
| 9–10 | Real-world breach history, compliance impact, and clean teardown including account-level settings. |
