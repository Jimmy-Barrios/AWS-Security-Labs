# LAB-001: CloudTrail — The Audit Log Foundation

| | |
|---|---|
| **Estimated cost** | < $0.10 per run |
| **Estimated time** | 45–60 minutes |
| **MITRE ATT&CK (Cloud)** | **T1562.001** — Impair Defenses: Disable or Modify Cloud Logging (Defense Evasion) |

---

## 1. Lab Overview

**Scenario:** A pen-test report lands on your desk: unexplained API activity in one of your AWS accounts. You ask for the CloudTrail logs. Turns out there’s no trail enabled in that region. GuardDuty, Security Hub, custom alerts—they all lean on the same audit log. No CloudTrail, no visibility. You’re blind.

This lab is about why that log is the foundation, what’s missing when it isn’t there, and how to turn it on and confirm you’re actually recording (and can query) API activity.

---

## 2. Learning Objectives

When you’re done you’ll be able to:

- Say why CloudTrail is the base layer for detection and IR in AWS (and what you lose without it).
- Spot the risk when a region has no trail—no API audit, no story.
- Turn on a CloudTrail trail with the CLI and confirm it’s actually logging.
- Run a CloudWatch Logs Insights query (or Event history) to see the simulated activity after you harden.

---

## 3. Architecture

**Services used**

| Service | Role in this lab |
|--------|-------------------|
| **S3** | Bucket to store CloudTrail log files (created by Terraform; trail created in Section 8). |
| **CloudTrail** | Trail is *not* created by Terraform (vulnerable state). You create and enable it via CLI during hardening. |
| **IAM** | Used by the “attacker” to call APIs (e.g. `CreateUser`, `ListBuckets`). No dedicated attacker user; use your lab credentials. |
| **CloudWatch Logs** (optional) | After hardening, you can deliver trail events to a log group for CloudWatch Logs Insights. |

**Data flow**

- **Vulnerable:** Your CLI hits IAM, S3, etc. No trail → nothing gets recorded. As defender you have nothing to query.
- **Hardened:** Trail is on, writing to the S3 bucket (and optionally CloudWatch). Same calls show up as events you can search and correlate.

**Diagram (text)**

```
[ You (attacker/defender) ]  -->  AWS API (e.g. IAM, S3)
                                        |
                    Vulnerable:         |    Hardened:
                    no trail            |    trail enabled
                                        v
                                    [ CloudTrail ]
                                        |
                                        v
                    [ S3 bucket ]  (and optionally CloudWatch Logs)
```

---

## 4. The Misconfiguration

**What's wrong**  
We only stand up an S3 bucket (and a policy so a trail *could* write to it). We don't create the trail. So in this region, no API activity is recorded. That's the lab's vulnerable state.

**Why you still see this in real orgs**  
Trails go missing or never get turned on for whatever reason:

- New regions turned on without extending logging.
- Legacy or “sandbox” accounts that never had a trail.
- Cost or “we only need it in one region” decisions that leave other regions unlogged.
- Oversight during initial setup.

Result are the same no audit trail.

**MITRE ATT&CK**  
No (or disabled) logging means no normal API story for defenders. That's **T1562.001 — Impair Defenses: Disable or Modify Cloud Logging** (Defense Evasion). We're modeling the *absence* of a trail rather than an attacker deleting one; either way you end up with nothing to detect or investigate.

---

## 5. Lab Setup

### Prerequisites

- **AWS CLI v2** installed and configured with credentials that can create S3 buckets, CloudTrail trails, and (if you use it) CloudWatch Logs.
- **Terraform 1.5+** installed.
- A lab or sandbox AWS account (or OU) where you’re allowed to create these resources and enable a trail.

### Deploy the vulnerable environment

From the `LAB-001/terraform` directory:

```bash
cd LAB-001/terraform
terraform init
terraform plan
terraform apply -auto-approve
```

Capture the outputs—you’ll need them in Section 8: `trail_bucket_name`, `trail_name`, and `region`. Use that region for all CLI commands below.

---

## 6. Attacker Perspective

You’ll run a few normal-looking API calls. In this setup there’s no trail, so none of this shows up in an audit log.

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

**Step 4 — (Optional) Simulate more activity**

```bash
aws sts get-caller-identity --region $(terraform output -raw region)
```

Bottom line: with no trail, none of this hits CloudTrail. No central API log, nothing to alert on or investigate.

---

## 7. Defender Perspective

### Before hardening: no trail, no visibility

Right now there’s no trail in this region, so the calls you ran in Section 6 never got logged. You can’t run a CloudTrail-based detection on activity that was never recorded. That’s the blind spot.

### After hardening: detection

Once you’ve enabled a trail (Section 8), new API activity shows up. Here’s how to find it.

**Option A — CloudWatch Logs Insights** (if you delivered the trail to a log group)

Point the query at your log group and the right time range:

```text
fields @timestamp, eventName, userIdentity.principalId, sourceIPAddress, userAgent, requestParameters
| filter eventSource = "iam.amazonaws.com" or eventSource = "s3.amazonaws.com"
| sort @timestamp desc
```

Narrow to IAM user creation:

```text
fields @timestamp, eventName, userIdentity.principalId, requestParameters.userName, sourceIPAddress
| filter eventName = "CreateUser"
| sort @timestamp desc
```

**Option B — Trail events in S3**

Log files land in the S3 bucket. Use the console (CloudTrail → Event history) or Athena on the trail’s S3 prefix for the same kind of lookups.

**Investigation checklist** (after the trail is on)

1. Confirm the trail is logging: `aws cloudtrail get-trail-status --name lab-001-audit-trail`
2. Run the Logs Insights query (or Event history / Athena) for the window when you re-ran the attacker steps
3. Line up `eventName`, `userIdentity`, and `sourceIPAddress` with what you ran

**GuardDuty**  
GuardDuty (and a lot of other detectors) runs on top of CloudTrail. No trail, no API audit data for them to work with. This lab doesn't hinge on a specific GuardDuty finding—the point is that the log has to exist first.

---

## 8. Harden & Verify

You fix this with the **AWS CLI** (or Console)—not Terraform. The idea is to mirror how you’d fix a live environment: change the config, then confirm the fix.

### 8.1 Create the trail and start logging (CLI)

Pull the Terraform outputs into shell variables (use your region if it’s different):

```bash
TRAIL_NAME=$(terraform output -raw trail_name)
BUCKET_NAME=$(terraform output -raw trail_bucket_name)
REGION=$(terraform output -raw region)
```

Create the trail:

```bash
aws cloudtrail create-trail \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$BUCKET_NAME" \
  --region "$REGION"
```

Start logging:

```bash
aws cloudtrail start-logging --name "$TRAIL_NAME" --region "$REGION"
```

Confirm it is logging:

```bash
aws cloudtrail get-trail-status --name "$TRAIL_NAME" --region "$REGION"
```

You should see `"IsLogging": true`.

### 8.2 (Optional) Send trail events to CloudWatch Logs

If you want to use Logs Insights, create a log group:

```bash
aws logs create-log-group --log-group-name "lab-001-cloudtrail-events" --region "$REGION"
```

You’ll need a role for CloudTrail to assume, the right policy, and a resource policy on the log group. For a quick run you can skip this and use **Event history** in the console (or the trail’s S3 files). If you do set up CloudWatch Logs, use the Section 7 queries.

### 8.3 Re-run the “attack” and verify you see it

Do the same kind of activity again so the new trail records it:

```bash
aws iam create-user --user-name lab-001-hardened-test-user
aws iam list-users --query "Users[?UserName=='lab-001-hardened-test-user']"
```

Give it a few minutes for events to show up, then:

- **Event history:** CloudTrail → Event history, filter by user name or event name (e.g. `CreateUser`).
- **Logs Insights:** If you set up delivery to a log group, run the Section 7 query for the last 5–10 minutes.

You should see the `CreateUser` (and related) events. That’s the closed loop: attack → enable trail → re-attack → confirm it’s logged. Fix verified.

### 8.4 Console alternative (create trail)

1. Open **CloudTrail** → **Trails** → **Create trail**.
2. Trail name: `lab-001-audit-trail`.
3. Storage: use the existing S3 bucket from Terraform output.
4. Create trail, then open the trail → **Start logging**.

Re-run the IAM user creation and confirm the event shows up in Event history.

---

## 9. Why It Matters

**Real world**  
A lot of breaches and abuse go undetected—or can’t be investigated—because there was no CloudTrail (or it wasn’t turned on in that region). Sometimes attackers turn it off; often it was never enabled. Either way you can’t answer “who did what, when, and from where.”

**Compliance and IR**  
CIS AWS Foundations and PCI DSS expect API logging; CloudTrail is how you do it. Incident response depends on it to reconstruct what happened. GuardDuty, Security Hub, and custom detectors all need that audit log. No trail in a region means no API-level detection there.

Turn on CloudTrail in every region you use, lock down the bucket and access, and treat it as the base layer. Everything else builds on that.

---

## 10. Teardown

### Remove the IAM users you created

Delete the test users (`lab-001-attacker-test-user`, `lab-001-hardened-test-user`). If they have access keys or other resources, remove those first:

```bash
# Example: delete access keys, then user (replace USER_NAME as needed)
aws iam list-access-keys --user-name lab-001-attacker-test-user
# If keys exist: aws iam delete-access-key --user-name lab-001-attacker-test-user --access-key-id <id>
aws iam delete-user --user-name lab-001-attacker-test-user

aws iam delete-user --user-name lab-001-hardened-test-user
```

### Delete the CloudTrail trail

The trail was created with the CLI, so Terraform won’t remove it. Delete it before you destroy the bucket:

```bash
aws cloudtrail stop-logging --name lab-001-audit-trail --region "$REGION"
aws cloudtrail delete-trail --name lab-001-audit-trail --region "$REGION"
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
- **IAM:** `aws iam list-users` — no lab test users left.

---

## Summary

| Section | What it covers |
|--------|----------------|
| 1–2 | Scenario (no trail = blind), and what you’ll get out of the lab. |
| 3–4 | What’s in play, data flow, and the misconfiguration (no trail) + MITRE T1562.001. |
| 5 | Terraform: S3 bucket only, no trail. |
| 6 | Attacker: API calls that never get logged. |
| 7 | Defender: nothing to query before hardening; after, detection via Event history or Logs Insights. |
| 8 | Harden with CLI (create trail, start logging), re-run attack, confirm events. |
| 9–10 | Why this matters in the real world and how to tear down cleanly. |
