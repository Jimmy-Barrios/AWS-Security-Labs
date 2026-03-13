# LAB-002: IAM Visibility: Detecting IAM Reconnaissance

|  |  |
| --- | --- |
| **Estimated cost** | < $0.10 per run |
| **Estimated time** | 45–60 minutes |
| **MITRE ATT&CK (Cloud)** | **T1087.004** - Account Discovery: Cloud Account (Discovery) |

---

## 1. Lab Overview

**Scenario:** A contractor's IAM role gets used to run `aws iam list-users` and `aws iam list-roles`. Someone gave that role broad IAM read permissions for "visibility" or "debugging." Now an attacker with those credentials can map your entire account users, roles, policies and hunt for privilege escalation paths. You might not even know it's happening unless you're looking for it.

This lab shows what IAM enumeration looks like from the attacker's side, how to detect it in CloudTrail, and how to fix it by applying least privilege.

---

## 2. Learning Objectives

When you're done you'll be able to:

- Explain why IAM enumeration is a reconnaissance technique and how it supports privilege escalation.
- Run realistic IAM enumeration commands (`list-users`, `list-roles`, `get-user`, `list-attached-role-policies`, etc.) using an assumed role.
- Use CloudWatch Logs Insights to detect IAM enumeration activity in CloudTrail.
- Harden the environment by removing unnecessary IAM read permissions and confirm the attack fails with AccessDenied.

---

## 3. Architecture

**Services used**

| Service | Role in this lab |
| --- | --- |
| **IAM** | Role `lab-002-attacker-role` with overly permissive IAM read permissions. You assume this role to simulate the attacker. |
| **CloudTrail** | Trail logs API calls to S3 and CloudWatch Logs so you can detect enumeration. |
| **S3** | Holds CloudTrail log files. |
| **CloudWatch Logs** | Log group for trail events; you query it with Logs Insights to find IAM enumeration. |

**Data flow**

- **Attacker:** You assume the role, run IAM enumeration commands. CloudTrail records every call.
- **Defender:** You query CloudWatch Logs Insights for events like `ListUsers`, `ListRoles`, `GetUser`, `GetRole`, etc., and correlate them to the assumed role.
- **Hardened:** After you remove the IAM enumeration policy from the role, the same commands return AccessDenied.

**Diagram (text)**

```
[ You ]  -->  Assume lab-002-attacker-role  -->  IAM API (ListUsers, ListRoles, GetUser, ...)
                                                              |
                                                              v
                                                        [ CloudTrail ]
                                                              |
                                    +-------------------------+-------------------------+
                                    v                                                       v
                            [ S3 bucket ]                                          [ CloudWatch Logs ]
                            (log files)                                            (Logs Insights query)
```

---

## 4. The Misconfiguration

**What's wrong**

The role `lab-002-attacker-role` has a policy that allows `iam:ListUsers`, `iam:ListRoles`, `iam:GetUser`, `iam:GetRole`, `iam:ListAttachedUserPolicies`, `iam:ListAttachedRolePolicies`, and related read actions. That's enough to enumerate users, roles, and policies across the account. An attacker with that role can map the environment and look for high-privilege roles or users to target.

**Why you still see this in real orgs**

Dev roles, contractor accounts, and automation scripts often get broad IAM read for "debugging," "visibility," or "we might need it later." Copy-pasted policies, legacy roles, and "just in case" permissions are common. The result is the same: anyone with that role can perform full IAM reconnaissance.

**MITRE ATT&CK**

**T1087.004 - Account Discovery: Cloud Account** (Discovery). Adversaries discover cloud accounts, users, and roles to support credential theft and privilege escalation. IAM enumeration is a core technique for this.

---

## 5. Lab Setup

### Prerequisites

- **AWS CLI v2** installed and configured with credentials that can create IAM roles, CloudTrail trails, S3 buckets, and CloudWatch Logs.
- **Terraform 1.5+** installed.
- A lab or sandbox AWS account where you're allowed to create these resources and assume roles.

### Authentication (AWS profile)

Terraform uses the same credential chain as the AWS CLI. If you use a **named profile** (e.g. `aws configure --profile my-lab`), set it before running Terraform:

```bash
export AWS_PROFILE=my-lab
```

Then run `terraform plan` and `terraform apply`. If you use the **default** profile, you don't need to set anything.

### Deploy the vulnerable environment

From the `LAB-002/terraform` directory:

```bash
cd "LAB-002 - IAM Visibility/terraform"
terraform init
terraform plan
terraform apply -auto-approve
```

When apply finishes, Terraform will print outputs: the attacker role ARN, the log group name, and the region. Jot down the role ARN—you'll need it to assume the role in Section 6. Use the same region for all CLI commands.

---

## 6. Attacker Perspective

The attacker flow here mirrors how a real threat actor would work: first discover what's in the account, find an interesting role, check if you can assume it, then assume it and dig deeper. Every step generates CloudTrail events the defender will look for in Section 7.

These first steps use your **base credentials** (the same ones you used to run `terraform apply`). You haven't assumed anything yet.

**Step 1: Confirm your starting identity**

```bash
aws sts get-caller-identity
```

This tells you who you are before any role assumption. Note it down — you'll compare it later.

**Step 2: Enumerate IAM roles**

```bash
aws iam list-roles
```

Scan the output. You're looking for roles that look like they have interesting permissions or were set up for a specific purpose. You'll see `lab-002-attacker-role` in the list.

**Step 3: Read the trust policy on the target role**

Before trying to assume a role, an attacker checks whether they're even allowed to. Pull the full role details:

```bash
aws iam get-role --role-name lab-002-attacker-role
```

Look at the `AssumeRolePolicyDocument` in the output. You'll see it trusts the account root (`arn:aws:iam::ACCOUNT_ID:root`), meaning any principal in the account with `sts:AssumeRole` can assume it. That's the green light.

**Step 4: Assume the role**

```bash
aws sts assume-role --role-arn ROLE_ARN --role-session-name lab002-attack
```

Replace `ROLE_ARN` with the ARN you found in Step 3 (or from `terraform output attacker_role_arn`). The output includes `AccessKeyId`, `SecretAccessKey`, and `SessionToken`. Export them so all following commands run as the assumed role:

```bash
export AWS_ACCESS_KEY_ID=<AccessKeyId from output>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey from output>
export AWS_SESSION_TOKEN=<SessionToken from output>
```

**Step 5: Confirm the identity switch**

```bash
aws sts get-caller-identity
```

You should now see `lab-002-attacker-role` in the ARN, not your base user. You're operating as the attacker role.

**Step 6: Enumerate users and roles**

Now enumerate from inside the assumed role:

```bash
aws iam list-users
aws iam list-roles
```

**Step 7: Discover permissions on roles and users**

In AWS, permissions can live in two places: **managed policies** (attached, reusable) and **inline policies** (embedded directly on the role or user). A thorough enumeration checks both — you won't know which is in use until you look.

Check managed policies on the role, then inline:

```bash
aws iam list-attached-role-policies --role-name lab-002-attacker-role
aws iam list-role-policies --role-name lab-002-attacker-role
```

`list-attached-role-policies` returns empty — no managed policies. But `list-role-policies` shows `IAMEnumerationPolicy`. Read it:

```bash
aws iam get-role-policy --role-name lab-002-attacker-role --policy-name IAMEnumerationPolicy
```

This reveals the full list of IAM actions the role has. Now apply the same pattern to a user:

```bash
aws iam list-attached-user-policies --user-name YOUR_IAM_USER_NAME
aws iam list-user-policies --user-name YOUR_IAM_USER_NAME
```

If any inline policy names appear, read them:

```bash
aws iam get-user-policy --user-name YOUR_IAM_USER_NAME --policy-name POLICY_NAME
```

At this point the attacker has a full map: users, roles, and their permissions. That's enough to identify escalation paths. CloudTrail has recorded every one of these calls.

**Step 8: Switch back to your base credentials**

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

---

## 7. Defender Perspective

After the attacker steps, you play defender: find evidence of the enumeration in CloudTrail.

**Check CloudWatch Logs Insights**

CloudTrail delivers events to the log group within a few minutes. Wait 2–5 minutes after running the attacker commands, then query.

1. Go to **CloudWatch** → **Logs** → **Log groups**.
2. Select the log group from Terraform output (e.g. `/aws/cloudtrail/lab-002-cloudtrail-events`).
3. Click **Query with Logs Insights**.
4. Select the log group and a time range that includes when you ran the enumeration.
5. Run this query:

```
fields @timestamp, eventName, userIdentity.sessionContext.sessionIssuer.userName, userIdentity.principalId, sourceIPAddress
| filter eventName in ["ListUsers", "ListRoles", "GetUser", "GetRole", "ListAttachedUserPolicies", "ListAttachedRolePolicies"]
| sort @timestamp desc
```

You should see the events from your assumed role. The `userIdentity.sessionContext.sessionIssuer.userName` (or `principalId`) will show the role `lab-002-attacker-role`.

**Narrow the query to the attacker role**

If you want to focus on activity from that role:

```
fields @timestamp, eventName, requestParameters.userName, requestParameters.roleName, sourceIPAddress
| filter eventName in ["ListUsers", "ListRoles", "GetUser", "GetRole", "ListAttachedUserPolicies", "ListAttachedRolePolicies"]
| filter userIdentity.sessionContext.sessionIssuer.userName = "lab-002-attacker-role"
| sort @timestamp desc
```

**What you've just seen**

IAM enumeration is detectable when CloudTrail is on and you're querying for it. The next step is to harden the role (Section 8), re-run the attack, and confirm it fails.

**GuardDuty**

GuardDuty can flag IAM enumeration in some configurations. For this lab we focus on CloudTrail and Logs Insights; you can explore GuardDuty findings separately if you have it enabled.

---

## 8. Harden & Verify

We fix this with the **AWS CLI** (or Console) by removing the IAM enumeration policy from the role. Then you re-run the attack and confirm it fails.

**Remove the policy via CLI**

The role has an inline policy named `IAMEnumerationPolicy`. Detach it:

```bash
aws iam delete-role-policy --role-name lab-002-attacker-role --policy-name IAMEnumerationPolicy
```

**Re-run the attacker steps**

Assume the role again and run the same enumeration commands:

```bash
# Obtain a new Session Token
aws sts assume-role --role-arn ROLE_ARN --role-session-name lab002-verify

# Export the temporary credentials as before
export AWS_ACCESS_KEY_ID=<AccessKeyId from output>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey from output>
export AWS_SESSION_TOKEN=<SessionToken from output>

aws iam list-users
```

You should get `AccessDenied` (or similar). The role no longer has IAM read permissions.

**Switch back to your credentials**

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

**Verification**

The closed loop: we had a role with IAM enumeration, we removed the policy, we re-ran the attack, and it failed. That confirms the fix.

**If you prefer the Console**

1. Go to **IAM** → **Roles** → **lab-002-attacker-role**.
2. Under **Permissions**, find the inline policy `IAMEnumerationPolicy`.
3. Click **Remove** (or delete the policy).
4. Confirm, then re-run the assume-role and `list-users` as above.

---

## 9. Why It Matters

**Real world**

Threat actors like Scattered Spider and APT29 (Cozy Bear) use cloud IAM enumeration to map accounts and find escalation paths. Overly permissive IAM read is common in dev and contractor roles. If you're not looking for `ListUsers`, `ListRoles`, and similar calls, you might miss the reconnaissance phase entirely.

**Compliance and least privilege**

CIS AWS Foundations and similar frameworks expect least privilege and monitoring of sensitive IAM actions. IAM enumeration should be restricted to roles that genuinely need it (e.g. security tooling), and those calls should be logged and reviewed.

Apply least privilege: grant only the IAM permissions a role actually needs. Monitor CloudTrail for enumeration and alert on unexpected patterns.

---

## 10. Teardown

### Destroy Terraform resources

From the `LAB-002 - IAM Visibility/terraform` directory:

```bash
terraform destroy -auto-approve
```

That removes the S3 bucket, CloudTrail trail, CloudWatch log group, IAM role for CloudTrail, and the attacker role (including any remaining policies).

If you hardened in Section 8 (removed the inline policy), Terraform may report that the policy is already gone. That's fine—Terraform will still remove the role and the rest of the resources.

### Verify

- No trail left: `aws cloudtrail describe-trails --region us-east-1` (or your region).
- Bucket is gone.
- Role `lab-002-attacker-role` is gone: `aws iam get-role --role-name lab-002-attacker-role` should return an error.
- Log group is gone: `aws logs describe-log-groups --log-group-name-prefix lab-002` should not list it.

---

## Summary

| Section | What it covers |
| --- | --- |
| 1–2 | Scenario (IAM enumeration = reconnaissance), and what you'll get out of the lab. |
| 3–4 | Architecture (IAM, CloudTrail, CloudWatch), data flow, and the misconfiguration (overly permissive IAM read) + MITRE T1087.004. |
| 5 | Terraform: CloudTrail, S3, CloudWatch, and the vulnerable IAM role. |
| 6 | Attacker: assume role, run IAM enumeration commands. |
| 7 | Defender: query CloudWatch Logs Insights for enumeration events. |
| 8 | Harden via CLI (or Console): remove IAM enumeration policy, re-run attack, confirm AccessDenied. |
| 9–10 | Why this matters in the real world and how to tear down cleanly. |
