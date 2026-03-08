# LAB-001: CloudTrail — The Audit Log Foundation

| | |
|---|---|
| **Estimated cost** | < $0.10 per run |
| **Estimated time** | 45–60 minutes |
| **MITRE ATT&CK (Cloud)** | **T1562.001** — Impair Defenses: Disable or Modify Cloud Logging (Defense Evasion) |

---

## 1. Lab Overview

**Scenario:** A pen-test report lands on your desk: unexplained API activity in one of your AWS accounts. You ask for the CloudTrail logs. Turns out there's no trail enabled in that region. GuardDuty, Security Hub, custom alerts—they all lean on the same audit log. No CloudTrail, no visibility. You're blind.

This lab is about why that log is the foundation, what's missing when it isn't there, and how to turn it on and confirm you're actually recording (and can query) API activity.

---

## 2. Learning Objectives

When you're done you'll be able to:

- Say why CloudTrail is the base layer for detection and IR in AWS (and what you lose without it).
- Spot the risk when a region has no trail—no API audit, no story.
- Turn on a CloudTrail trail with the CLI and confirm it's actually logging.
- Run a CloudWatch Logs Insights query (or Event history) to see the simulated activity after you harden.

---

## 3. Architecture

**Services used**

| Service | Role in this lab |
|--------|-------------------|
| **S3** | Holds CloudTrail log files. Terraform creates the bucket; you create the trail in Section 8. |
| **CloudTrail** | Trail is *not* created by Terraform (vulnerable state). You create and enable it via CLI during hardening. |
| **CloudWatch Logs** | Log group for trail events so you can query with Logs Insights. Not present in the vulnerable state; you create it and wire the trail to it in Section 8. |
| **IAM** | Your lab credentials run the "attacker" API calls; during hardening you create a role so CloudTrail can write to CloudWatch Logs. |

**Data flow**

- **Vulnerable:** No trail, no CloudWatch log group. API calls hit IAM, S3, etc., but nothing is recorded. As defender you have no CloudTrail events and no CloudWatch logs to query.
- **Hardened:** Trail is on, writing to the S3 bucket *and* to a CloudWatch Logs log group. Same calls show up as events in S3 and in Logs Insights so you can search and correlate.

**Diagram (text)**

```
[ You (attacker/defender) ]  -->  AWS API (e.g. IAM, S3)
                                        |
                    Vulnerable:         |    Hardened:
                    no trail            |    trail enabled
                    no CloudWatch       |    CloudWatch Logs
                                        v
                                    [ CloudTrail ]
                                        |
                        +---------------+---------------+
                        v                               v
                [ S3 bucket ]                  [ CloudWatch Logs ]
                (log files)                    (Logs Insights)
```

---

## 4. The Misconfiguration

**What's wrong**  
We only stand up an S3 bucket (and a policy so a trail *could* write to it). We don't create the trail, and we don't create a CloudWatch Logs log group or wire anything to it. So in this region, no API activity is recorded and there's no CloudWatch log stream to query. That's the lab's vulnerable state.

**Why you still see this in real orgs**  
Trails (and CloudWatch delivery) go missing or never get turned on for boring reasons: new regions enabled without extending logging, legacy or sandbox accounts that never had a trail, "we only need it in one region," or plain oversight. Result is the same—no audit trail, no real-time log querying.

**MITRE ATT&CK**  
No (or disabled) logging means no normal API story for defenders. That's **T1562.001 — Impair Defenses: Disable or Modify Cloud Logging** (Defense Evasion). We're modeling the *absence* of a trail rather than an attacker deleting one; either way you end up with nothing to detect or investigate.

---

## 5. Lab Setup

### Prerequisites

- **AWS CLI v2** installed and configured with credentials that can create S3 buckets, CloudTrail trails, and CloudWatch Logs.
- **Terraform 1.5+** installed.
- A lab or sandbox AWS account (or OU) where you're allowed to create these resources and enable a trail.

### Authentication (AWS profile)

Terraform uses the same credential chain as the AWS CLI. If you use a **named profile** (e.g. `aws configure --profile my-lab`), set it before running Terraform:

```bash
export AWS_PROFILE=my-lab
```

Then run `terraform plan` and `terraform apply` as usual. If you use the **default** profile, you don't need to set anything.

### Deploy the vulnerable environment

From the `LAB-001/terraform` directory:

```bash
cd LAB-001/terraform
terraform init
terraform plan
terraform apply -auto-approve
```

Use the same profile (or `export AWS_PROFILE=...`) for any `aws` CLI commands in the lab so they hit the same account.

Capture the outputs—you'll need them in Section 8: `trail_bucket_name`, `trail_name`, and `region`. Use that region for all CLI commands below.

---

## 6. Attacker Perspective

You'll run a few normal-looking API calls. In this setup there's no trail, so none of this shows up in an audit log.

**Step 1 — List S3 buckets**

```bash
aws s3api list-buckets --region $(terraform output -raw region)
```

**Step 2 — Create an IAM user (simulating account manipulation)**

Use a unique name so you can clean it up in teardown:

```bash
aws iam create-user --user-name lab-001-attacker-test-user
```

**Step 3 — List IAM users to confirm**

```bash
aws iam list-users --query "Users[?UserName=='lab-001-attacker-test-user']"
```

**Step 4 — Simulate more activity**

```bash
aws sts get-caller-identity --region $(terraform output -raw region)
```

Bottom line: with no trail, none of this hits CloudTrail. No central API log, nothing to alert on or investigate.

---

## 7. Defender Perspective — Discovering the gap

After the attacker steps in Section 6, you play defender: try to find evidence of what happened.

**Check for CloudTrail**

- In the console: **CloudTrail** → **Event history**. Look for the API calls you ran (e.g. `CreateUser`, `ListBuckets`).
- Or list trails: `aws cloudtrail describe-trails --region $(terraform output -raw region)`.

You'll find no trail in this region (or no events for your actions). Nothing was recorded.

**Check for CloudWatch Logs**

- In the console: **CloudWatch** → **Log groups**. Look for a log group that would hold CloudTrail events.
- Or: `aws logs describe-log-groups --log-group-name-prefix lab-001 --region $(terraform output -raw region)`.

There's no CloudWatch log group set up for this trail. No Logs Insights, no real-time querying.

**What you've just seen**  
This is the misconfiguration in practice: no CloudTrail trail and no CloudWatch Logs delivery. You have no audit trail and no log stream to query. Next step is to fix it (Section 8), then re-run the attack and confirm you can see it as defender.

**GuardDuty**  
GuardDuty and other detectors run on CloudTrail (and other data). No trail, no API audit for them. The point here is that the log has to exist first.

---

## 8. Harden & Verify

You fix this with the **AWS CLI** (or Console)—not Terraform. You will enable CloudTrail and CloudWatch Logs (both required in this lab), then re-run the attacker steps and confirm you can see the activity as defender.

### 8.1 Set variables and create the trail

Pull the Terraform outputs into shell variables (use your region if it's different):

```bash
TRAIL_NAME=$(terraform output -raw trail_name)
BUCKET_NAME=$(terraform output -raw trail_bucket_name)
REGION=$(terraform output -raw region)
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

Create the trail:

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$BUCKET_NAME" \
  --region "$REGION"
```

### 8.2 Create CloudWatch Logs (required)

Create the log group:

```bash
aws logs create-log-group --log-group-name "lab-001-cloudtrail-events" --region "$REGION"
```

Create an IAM role that CloudTrail can assume to write to the log group. From the directory where you're running commands:

```bash
cat > trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
aws iam create-role --role-name Lab001CloudTrailCloudWatchRole --assume-role-policy-document file://trust-policy.json
```

Create and attach an inline policy so the role can write to the log group (use your `REGION` and `ACCOUNT_ID` from above):

```bash
cat > cloudtrail-logs-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:lab-001-cloudtrail-events:*"
    }
  ]
}
EOF
aws iam put-role-policy --role-name Lab001CloudTrailCloudWatchRole --policy-name CloudTrailLogsPolicy --policy-document file://cloudtrail-logs-policy.json
```

Put a resource policy on the log group so CloudTrail can write:

```bash
cat > log-group-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailCreateLogStream",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "logs:CreateLogStream",
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:lab-001-cloudtrail-events:*"
    },
    {
      "Sid": "AWSCloudTrailPutLogEvents",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "logs:PutLogEvents",
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:lab-001-cloudtrail-events:*",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"
        }
      }
    }
  ]
}
EOF
aws logs put-resource-policy --policy-name Lab001CloudTrailToCloudWatch --policy-document file://log-group-policy.json
```

Update the trail to deliver to CloudWatch Logs:

```bash
LOG_GROUP_ARN="arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:lab-001-cloudtrail-events:*"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/Lab001CloudTrailCloudWatchRole"
aws cloudtrail update-trail --name "$TRAIL_NAME" --cloud-watch-logs-log-group-arn "$LOG_GROUP_ARN" --cloud-watch-logs-role-arn "$ROLE_ARN" --region "$REGION"
```

Start logging:

```bash
aws cloudtrail start-logging --name "$TRAIL_NAME" --region "$REGION"
```

Confirm it's logging:

```bash
aws cloudtrail get-trail-status --name "$TRAIL_NAME" --region "$REGION"
```

You should see `"IsLogging": true`.

### 8.3 Re-run the attacker steps

Do the same kind of activity again so the new trail (and CloudWatch) records it:

```bash
aws iam create-user --user-name lab-001-hardened-test-user
aws iam list-users --query "Users[?UserName=='lab-001-hardened-test-user']"
```

### 8.4 Defender perspective — detection

Give it a few minutes for events to show up, then run detection.

**CloudWatch Logs Insights**

In **CloudWatch** → **Log groups** → **lab-001-cloudtrail-events** → **Query with Logs Insights**, select the log group and time range, then run:

```text
fields @timestamp, eventName, userIdentity.principalId, requestParameters.userName, sourceIPAddress
| filter eventName = "CreateUser"
| sort @timestamp desc
```

Broader query for IAM and S3:

```text
fields @timestamp, eventName, userIdentity.principalId, sourceIPAddress, userAgent, requestParameters
| filter eventSource = "iam.amazonaws.com" or eventSource = "s3.amazonaws.com"
| sort @timestamp desc
```

**CloudTrail Event history**

In **CloudTrail** → **Event history**, filter by user name or event name (e.g. `CreateUser`). You should see the `CreateUser` (and related) events.

**Closed loop**  
Attack → discover no logs (Section 7) → harden with trail + CloudWatch (Section 8) → re-attack → confirm events in Logs Insights and Event history. Fix verified.

### 8.5 Console alternative (create trail and CloudWatch)

1. **CloudTrail** → **Trails** → **Create trail**. Name: `lab-001-audit-trail`. Storage: existing S3 bucket from Terraform output. Under **CloudWatch Logs**, create a new log group (e.g. `lab-001-cloudtrail-events`) and let the console create the role, or use an existing role that has permission to write to that log group.
2. Create trail, then **Start logging**.
3. Re-run the IAM user creation and confirm the event in Event history and in the log group.

---

## 9. Why It Matters

**Real world**  
A lot of breaches and abuse go undetected—or can't be investigated—because there was no CloudTrail (or it wasn't turned on in that region). Sometimes attackers turn it off; often it was never enabled. Either way you can't answer "who did what, when, and from where."

**Compliance and IR**  
CIS AWS Foundations and PCI DSS expect API logging; CloudTrail is how you do it. Incident response depends on it to reconstruct what happened. GuardDuty, Security Hub, and custom detectors all need that audit log. No trail in a region means no API-level detection there.

Turn on CloudTrail in every region you use, deliver to CloudWatch Logs for real-time querying, lock down the bucket and access, and treat it as the base layer. Everything else builds on that.

---

## 10. Teardown

### Remove the IAM users you created

Delete the test users (`lab-001-attacker-test-user`, `lab-001-hardened-test-user`). If they have access keys or other resources, remove those first:

```bash
aws iam list-access-keys --user-name lab-001-attacker-test-user
# If keys exist: aws iam delete-access-key --user-name lab-001-attacker-test-user --access-key-id <id>
aws iam delete-user --user-name lab-001-attacker-test-user

aws iam delete-user --user-name lab-001-hardened-test-user
```

### Delete the CloudTrail trail and CloudWatch resources

The trail was created with the CLI, so Terraform won't remove it. Delete it before you destroy the bucket:

```bash
aws cloudtrail stop-logging --name lab-001-audit-trail --region "$REGION"
aws cloudtrail delete-trail --name lab-001-audit-trail --region "$REGION"
```

Delete the log group and the IAM role you created:

```bash
aws logs delete-log-group --log-group-name lab-001-cloudtrail-events --region "$REGION"
aws iam delete-role-policy --role-name Lab001CloudTrailCloudWatchRole --policy-name CloudTrailLogsPolicy
aws iam delete-role --role-name Lab001CloudTrailCloudWatchRole
```

Use the same `REGION` and trail name you used in Section 8.

### Destroy Terraform resources

From `LAB-001/terraform`:

```bash
terraform destroy -auto-approve
```

### Verify

- **Trail:** `aws cloudtrail describe-trails --region $REGION` — `lab-001-audit-trail` should be gone.
- **S3:** The bucket from `trail_bucket_name` is removed after `terraform destroy`.
- **IAM:** `aws iam list-users` — no lab test users left; role `Lab001CloudTrailCloudWatchRole` deleted.
- **CloudWatch:** Log group `lab-001-cloudtrail-events` deleted.

---

## Summary

| Section | What it covers |
|--------|----------------|
| 1–2 | Scenario (no trail = blind), and what you'll get out of the lab. |
| 3–4 | Architecture (S3, CloudTrail, CloudWatch Logs), data flow, and the misconfiguration (no trail, no CloudWatch) + MITRE T1562.001. |
| 5 | Terraform: S3 bucket only, no trail, no CloudWatch. |
| 6 | Attacker: API calls that never get logged. |
| 7 | Defender: try to check CloudTrail and CloudWatch logs; discover neither is set up (the gap). |
| 8 | Harden with CLI (trail + CloudWatch Logs required), re-run attack, then defender runs detection (Logs Insights + Event history). |
| 9–10 | Why this matters in the real world and how to tear down cleanly. |
