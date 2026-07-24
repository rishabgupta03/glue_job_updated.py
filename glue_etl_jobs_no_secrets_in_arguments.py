#!/usr/bin/env python3
"""
Control      : Glue ETL Job has no secrets in Default Arguments
Service      : AWS Glue (regional service)
Logic        : For every Glue Job, inspect DefaultArguments (the --key value
               pairs baked into the job). Flag any argument whose KEY looks
               like a secret (password/token/api_key/etc.) unless its VALUE
               is a reference to a secure store (Secrets Manager / SSM),
               and flag any VALUE that itself looks like a raw AWS access key.
               Actual secret values are never written to evidence/CSV - only
               the offending argument key and a masked preview.
"""

import argparse
import csv
import re
import boto3
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "Glue ETL Job - No Secrets in Default Arguments"

# Key name fragments that suggest a credential is being stored
SUSPICIOUS_KEY_PATTERNS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "access_key", "accesskey", "credential", "auth", "private_key", "privatekey",
]

# Value patterns that indicate a literal secret regardless of key name
AWS_ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")

# Safe value prefixes - job is pulling from a secure store, not hardcoding
SAFE_VALUE_PREFIXES = ("arn:aws:secretsmanager:", "ssm:", "arn:aws:ssm:")

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        sts = boto3.Session().client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="control-audit"
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]


# ==================================================
# HELPERS
# ==================================================
def classify_error(e):
    """Turn a ClientError into a short (code, human_reason) pair."""
    code = e.response.get("Error", {}).get("Code", "Unknown")
    reasons = {
        "AccessDeniedException": "Access denied for Glue API",
        "UnauthorizedOperation": "Access denied for Glue API",
        "EntityNotFoundException": "Referenced resource not found",
        "ThrottlingException": "Throttled by AWS API",
    }
    return code, reasons.get(code, f"AWS error: {code}")


def mask(value):
    """Never expose a real secret value in evidence - short masked preview only."""
    value = str(value)
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}{'*' * 6}{value[-2:]}"


def is_safe_reference(value):
    return str(value).startswith(SAFE_VALUE_PREFIXES)


def scan_default_arguments(default_args):
    """
    Given a Glue Job's DefaultArguments dict, return (is_compliant, evidence).
    Never leak the raw secret value.
    """
    if not default_args:
        return True, "No default arguments defined"

    findings = []
    for key, value in default_args.items():
        clean_key = key.lstrip("-").lower()

        key_is_suspicious = any(p in clean_key for p in SUSPICIOUS_KEY_PATTERNS)
        value_is_aws_key = bool(AWS_ACCESS_KEY_RE.search(str(value)))

        if value_is_aws_key:
            findings.append(f"{key}=<AWS access key literal:{mask(value)}>")
            continue

        if key_is_suspicious and not is_safe_reference(value):
            findings.append(f"{key}=<hardcoded value:{mask(value)}>")

    if findings:
        return False, "Possible hardcoded secret(s) in default arguments: " + "; ".join(findings)
    return True, "No hardcoded secrets detected in default arguments"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            glue = session.client("glue", region_name=region)
        except ClientError as e:
            _, reason = classify_error(e)
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": f"Could not create client - {reason}",
            })
            continue

        try:
            paginator = glue.get_paginator("get_jobs")
            jobs = []
            for page in paginator.paginate():
                jobs.extend(page.get("Jobs", []))
        except ClientError as e:
            code, reason = classify_error(e)
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": f"Could not list jobs - {reason} ({code})",
            })
            continue

        for job in jobs:
            total_checked += 1
            name = job.get("Name", "N/A")
            arn = f"arn:aws:glue:{region}:{account_id}:job/{name}"
            default_args = job.get("DefaultArguments", {})

            is_compliant, evidence = scan_default_arguments(default_args)
            if is_compliant:
                compliant += 1
                status = "COMPLIANT"
            else:
                non_compliant += 1
                status = "NON_COMPLIANT"

            results.append({
                "Region": region, "ResourceId": name, "ResourceArn": arn,
                "Status": status, "Evidence": evidence,
            })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"glue_job_no_secrets_in_arguments_{account_id}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({"Account": account_id, **row})
    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(description=CONTROL_NAME)
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    csv_file = write_csv(results, account_id)

    print("\n====================================================")
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("====================================================\n")


if __name__ == "__main__":
    main()
