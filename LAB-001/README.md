# LAB-001: CloudTrail The Audit Log Foundation

|  |  |
| --- | --- |
| **Estimated cost** | < $0.10 per run |
| **Estimated time** | 45–60 minutes |
| **MITRE ATT&CK (Cloud)** | **T1562.001** - Impair Defenses: Disable or Modify Cloud Logging (Defense Evasion) |

---

## 1. Lab Overview

**Scenario:** A pen-test report lands on your desk: unexplained API activity in one of your AWS accounts. You ask for the CloudTrail logs. Turns out there's no trail enabled in that region. GuardDuty, Security Hub, custom alerts they all lean on the same audit log. No CloudTrail, no visibility. You're blind.

This lab is about why that log is the foundation, what's missing when it isn't there, and how to turn it on and confirm you're actually recording (and can query) API activity.

---

## 2. Learning Objectives

When you're done you'll be able to:

- Say why CloudTrail is the base for detection and IR in AWS and what you lose without it.
- Spot the risk when a region has no trail no API audit, no story.
- Turn on a CloudTrail trail with the CLI and confirm it's actually logging.
- Run a CloudWatch Logs Insights query (or Event history) to see the simulated activity after you harden the environment.
- We use Terraform to help us build skills with IaC

---

## 3. Architecture

**Services used**

| Service | Role in this lab |
| --- | --- |
| **S3** | Holds CloudTrail log files. Terraform creates the bucket; you create the trail in Section 8. |
| **CloudTrail** | Trail is *not* created by Terraform (vulnerable state). You create and enable it via CLI during hardening. |
| **CloudWatch Logs** | Log group for trail events so you can query with Logs Insights. Not present in the vulnerable state; you create it and wire the trail to it in Section 8. |
| **IAM** | Your lab credentials run the "attacker" API calls; when you add CloudWatch to the trail (Console or CLI), a role is needed so CloudTrail can write to the log group the Console can create it for you. |

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

We only stand up an S3 bucket (and a policy so a trail could write to it). We don't create the trail, and we don't create a CloudWatch Logs log group or wire anything to it. So in this region, no API activity is recorded and there's no CloudWatch log stream to query. That's the lab's vulnerable state.

**Why you still see this in real orgs**

Trails (and CloudWatch delivery) go missing or never get turned on for different reasons: new regions enabled without extending logging, legacy or sandbox accounts that never had a trail, "we only need it in one region," or just oversight. Result is the same no audit trail, no real-time log querying.

**MITRE ATT&CK**

No (or disabled) logging means no normal API story for defenders. That's **T1562.001 - Impair Defenses: Disable or Modify Cloud Logging** (Defense Evasion). We're modeling the absence of a trail rather than an attacker deleting one; either way you end up with nothing to detect or investigate.

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

Then run `terraform plan` and `terraform apply`. If you use the **default** profile, you don't need to set anything.

### Deploy the vulnerable environment

From the `LAB-001/terraform` directory:

```bash
cd LAB-001/terraform
terraform init
terraform plan
terraform apply -auto-approve
```

Use the same profile (or `export AWS_PROFILE=...`) for any `aws` CLI commands in the lab so they hit the same account.

When apply finishes, Terraform will print a few outputs: the S3 bucket name for the trail, the trail name we'll use later, and the region. Jot down the bucket name and region you'll need them when you create the trail in Section 8. Everything in this lab uses that same region (e.g. if you're in us-east-1, stick with it for the CLI commands below).

---

## 6. Attacker Perspective

You'll run a few normal looking API calls. In this setup there's no trail, so none of this shows up in an audit log.

**Step 1: List S3 buckets**

Run this in the same region you deployed Terraform to (e.g. us-east-1):

```bash
aws s3api list-buckets --region us-east-1
```

*(Replace us-east-1 with your region if different.)*

**Step 2: Create an IAM user (simulating account manipulation)**

Use a unique name so you can clean it up in teardown:

```bash
aws iam create-user --user-name lab-001-attacker-test-user
```

**Step 3: List IAM users to confirm**

```bash
aws iam list-users --query "Users[?UserName=='lab-001-attacker-test-user']"
```

**Step 4: Simulate more activity**

```bash
aws sts get-caller-identity --region us-east-1
```

*(Same region as above.)*

Bottom line: with no trail, none of this hits CloudTrail. No central API log, nothing to alert on or investigate.

---

## 7. Defender Perspective, Discovering the gap

After the attacker steps in Section 6, you play defender: try to find evidence of what happened.

**Check for CloudTrail**

- In the console:
    - **CloudTrail** → **Event history**. Look for the API calls you ran (e.g. `CreateUser`, `ListBuckets`).
- Or from the CLI
    - List trails in your region: `aws cloudtrail describe-trails --region us-east-1` (use your region).

You'll find no trail in this region (or no events for your actions). Nothing was recorded.

**Check for CloudWatch Logs**

- In the console:
    - **CloudWatch** → **Log groups**. Look for a log group that would hold CloudTrail events.
- Or from the CLI:
    - `aws logs describe-log-groups --log-group-name-prefix lab-001 --region us-east-1` (use your region).

There's no CloudWatch log group set up for this trail. No Logs Insights, no real-time querying.

**What you've just seen**

This is the misconfiguration in practice: no CloudTrail trail and no CloudWatch Logs delivery. You have no audit trail and no log stream to query. Next step is to fix it (Section 8), then re-run the attack and confirm you can see it as defender.

**GuardDuty** and other detectors run on CloudTrail and other data. No trail, no API audit logs means no data for GuardDuty to detect. The point here is that the log has to exist first.

---

## 8. Harden & Verify

We can fix this in the **Console** or with the **AWS CLI**. We'll turn on CloudTrail and send events to CloudWatch Logs so you can query them. Then you re-run the same attacker steps and, as a defender, confirm you can see the activity.

**Setting up via the Console:**

Using the console the CloudWatch log group and IAM role needed will be created for you during the set up process. If you have experience creating policies, roles this is something you can do via the AWS CLI.

1. Go to **CloudTrail** → **Trails** → **Create trail**.
2. **Trail name:** `lab-001-audit-trail` (or whatever you like; we use this name in the terraform teardown).
3. **S3 Bucket location:** Use the existing S3 bucket Terraform gave you (something like `lab-001-cloudtrail-logs-123456789012`). It's in your Terraform output as `trail_bucket_name`.
4. Under **CloudWatch Logs**, choose to create a new log group. Name it something like `lab-001-cloudtrail-events`. When you do that, the console will offer to create an IAM role so CloudTrail can write to the log group, accept that. It saves you from building the role and policies by manually.
5. Create the trail, then open it and click **Start logging**.

That's it. The trail is now recording API calls and sending them to both S3 and CloudWatch Logs.

**Re-run the attacker steps**

Do the same thing you did in Section 6: create another IAM user so the new trail has something to record. For example:

```bash
aws iam create-user --user-name lab-001-hardened-test-user
```

Use the same region you've been using (e.g. us-east-1) for your profile. You don't need to run a bunch of other commands the point is to generate a few events that will show up in the trail.

**Defender steps: confirm you can see it**

Wait a minute or two for events to land, then check.

- **CloudTrail Event history:** In the console, go to **CloudTrail** → **Event history**. Filter by event name `CreateUser` (or browse). You should see the call that created `lab-001-hardened-test-user`.
- **CloudWatch Logs Insights:** Go to **CloudWatch** → **Log groups** → your log group (e.g. `lab-001-cloudtrail-events`) → **Query with Logs Insights**. Select the log group and a time range that includes when you ran the create-user command. Try this query:

```
fields @timestamp, eventName, userIdentity.principalId, requestParameters.userName, sourceIPAddress
| filter eventName = "CreateUser"
| sort @timestamp desc
```

You should see your event. That's the closed loop: we had no logs, we turned on the trail and CloudWatch, we did the same kind of attack again, and now we can see it. This confirms our fix of enabling CloudTrail and CloudWatch is working.

**If you prefer the CLI**

You can do the same thing from the command line. 

- You'll need to:
    - Create the trail and point it at your S3 bucket,
    - Create a log group
    - Create an IAM role that CloudTrail can assume to write to that log group (with the right trust policy and permissions to write logs), and put a resource policy on the log group so CloudTrail is allowed to write.
    - Update the trail with the log group ARN and role ARN and start logging.
- AWS documents this in [Sending CloudTrail events to CloudWatch Logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html) the "Create the role" and "Add permissions" sections walk through the role and the log group resource policy. Once the trail is created and logging, re-run the create-user command and check Event history or Logs Insights as above.

---

## 9. Why It Matters

**Real world**

A lot of breaches and abuse go undetected or can't be investigated because there was no CloudTrail logs (or it wasn't turned on in that region). Sometimes attackers turn it off; often it was never enabled. Either way you can't answer "who did what, when, and from where."

**Compliance and Incident Response (IR)**

CIS AWS Foundations and PCI DSS expect API logging; CloudTrail is how you do it. Incident response depends on it to reconstruct what happened. GuardDuty, Security Hub, and custom detectors all need that audit log. No trail in a region means no API-level detection there.

Turn on CloudTrail in every region you use, deliver to CloudWatch Logs for real-time querying, lock down the bucket and access, and treat it as the base layer. Everything else builds on that.

---

## 10. Teardown

### Remove the IAM users you created

Delete the two test users: `lab-001-attacker-test-user` and `lab-001-hardened-test-user`. If either one has access keys, delete those first (IAM → Users → user → Security credentials → Access keys). Then delete the user. From the CLI:

```bash
aws iam delete-user --user-name lab-001-attacker-test-user
aws iam delete-user --user-name lab-001-hardened-test-user
```

(If you get "cannot delete user with existing keys," list and delete the keys first, then delete the user.)

### Remove the trail and CloudWatch stuff

Terraform didn't create the trail or the log group you did that in the console (or CLI). So you have to remove them manually before destroying the Terraform bucket.

**In the console:** CloudTrail → Trails → your trail → Delete. When it asks, confirm. Then go to CloudWatch → Log groups and delete the log group you created (e.g. `lab-001-cloudtrail-events`). If the console created an IAM role for CloudTrail to use, you can delete that role in IAM (it's usually named something like `CloudTrail-CloudWatchLogs-Role` or similar—check the trail's configuration to see which role it used).

**From the CLI:** Use the same region and trail name you used when you created the trail. For example, if your trail is `lab-001-audit-trail` and your region is us-east-1:

```bash
aws cloudtrail stop-logging --name lab-001-audit-trail --region us-east-1
aws cloudtrail delete-trail --name lab-001-audit-trail --region us-east-1
aws logs delete-log-group --log-group-name lab-001-cloudtrail-events --region us-east-1
```

If you created a custom role (e.g. `Lab001CloudTrailCloudWatchRole`), remove its policies and then delete the role. If the console created the role, find it in IAM and delete it there.

### Destroy Terraform resources

From the `LAB-001/terraform` directory:

```bash
terraform destroy -auto-approve
```

That removes the S3 bucket and the bucket policy.

### Verify

- No trail left: in the console or `aws cloudtrail describe-trails --region us-east-1` (or your region).
- Bucket is gone after destroy.
- The two test users are gone; any role you created for CloudWatch is gone; the log group is gone.

---

## Summary

| Section | What it covers |
| --- | --- |
| 1–2 | Scenario (no trail = blind), and what you'll get out of the lab. |
| 3–4 | Architecture (S3, CloudTrail, CloudWatch Logs), data flow, and the misconfiguration (no trail, no CloudWatch) + MITRE T1562.001. |
| 5 | Terraform: S3 bucket only, no trail, no CloudWatch. |
| 6 | Attacker: API calls that never get logged. |
| 7 | Defender: try to check CloudTrail and CloudWatch logs; discover neither is set up (the gap). |
| 8 | Harden in Console (or CLI): trail + CloudWatch Logs, re-run attack, then defender checks Event history and Logs Insights. |
| 9–10 | Why this matters in the real world and how to tear down cleanly. |