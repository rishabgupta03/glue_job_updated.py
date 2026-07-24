#!/usr/bin/env python3
"""
Control: Glue Data Catalog is not publicly accessible via its resource
policy.

Checks the Data Catalog resource policy in every enabled region and
verifies it does not grant access to Principal "*" without a restricting
Condition. A Data Catalog with no resource policy attached at all is
compliant by default (no policy means no cross-account/public grant is
possible). This is a single region-wide resource policy, not a
per-resource setting, so this control is evaluated once per region.
"""

import boto3
import argparse
import csv
import json
from datetime import datetime
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
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
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================
def error_evidence(e):
    """Classify a ClientError into a short code + human-readable evidence string."""
    code = e.response.get("Error", {}).get("Code", "UnknownError")
    msg = e.response.get("Error", {}).get("Message", str(e))
    return code, f"{code}: {msg}"[:200]


def build_catalog_arn(region, account_id):
    return f"arn:aws:glue:{region}:{account_id}:catalog"


def analyze_policy_for_public_access(policy_json):
    """
    Returns a list of finding strings describing any statement that grants
    access to Principal "*" without a restricting Condition.
    """
    findings = []
    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, TypeError):
        return ["Could not parse resource policy JSON"]

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        has_condition = bool(statement.get("Condition"))

        is_wildcard = False
        if principal == "*":
            is_wildcard = True
        elif isinstance(principal, dict):
            for value in principal.values():
                if value == "*" or (isinstance(value, list) and "*" in value):
                    is_wildcard = True

        if is_wildcard and not has_condition:
            findings.append("Statement grants access to Principal '*' with no restricting Condition")
        elif is_wildcard and has_condition:
            findings.append("Statement grants access to Principal '*' restricted only by a Condition - review manually")

    return findings


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
        total_checked += 1
        catalog_arn = build_catalog_arn(region, account_id)

        try:
            glue = session.client("glue", region_name=region)
            response = glue.get_resource_policy()
            policy_json = response.get("PolicyInJson")
        except ClientError as e:
            code, evidence = error_evidence(e)

            # --- No policy attached at all is a normal, compliant state ---
            if code == "EntityNotFoundException":
                compliant += 1
                results.append({
                    "Region": region,
                    "ResourceArn": catalog_arn,
                    "Status": "COMPLIANT",
                    "Evidence": "No resource policy attached - public/cross-account access is not possible"
                })
                continue

            skipped += 1
            total_checked -= 1
            results.append({
                "Region": region,
                "ResourceArn": catalog_arn,
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        if not policy_json:
            compliant += 1
            results.append({
                "Region": region,
                "ResourceArn": catalog_arn,
                "Status": "COMPLIANT",
                "Evidence": "No resource policy attached - public/cross-account access is not possible"
            })
            continue

        findings = analyze_policy_for_public_access(policy_json)

        if not findings:
            status = "COMPLIANT"
            compliant += 1
            evidence = "Resource policy present but does not grant public access"
        else:
            status = "NON_COMPLIANT"
            non_compliant += 1
            evidence = "; ".join(findings)

        results.append({
            "Region": region,
            "ResourceArn": catalog_arn,
            "Status": status,
            "Evidence": evidence
        })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"glue_catalog_not_public_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "ResourceArn": row["ResourceArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check Glue Data Catalog is not publicly accessible via its resource policy."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "Glue - Data Catalog Not Publicly Accessible via Resource Policy"

    results, total_checked, compliant, non_compliant, skipped = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n====================================================")
    print(f"CONTROL: {control_name}")
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
