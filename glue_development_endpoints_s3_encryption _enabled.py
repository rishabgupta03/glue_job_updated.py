#!/usr/bin/env python3
"""
Control      : Glue Development Endpoints have S3 encryption enabled
Service      : AWS Glue (regional service)
Logic        : For every Glue Dev Endpoint, resolve its attached Security
               Configuration and confirm S3Encryption mode is not DISABLED.
"""

import argparse
import csv
import boto3
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "Glue Dev Endpoint - S3 Encryption Enabled"

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


def s3_encryption_status(security_config):
    """
    Given a Glue SecurityConfiguration dict, return (is_compliant, evidence).
    Compliant only if at least one S3Encryption entry has a mode != DISABLED.
    """
    s3_settings = (
        security_config.get("EncryptionConfiguration", {}).get("S3Encryption", [])
    )
    if not s3_settings:
        return False, "No S3Encryption block defined in security configuration"

    modes = [s.get("S3EncryptionMode", "DISABLED") for s in s3_settings]
    if any(m != "DISABLED" for m in modes):
        active = [m for m in modes if m != "DISABLED"]
        return True, f"S3 encryption enabled ({', '.join(active)})"
    return False, "S3Encryption present but mode is DISABLED"


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
            paginator = glue.get_paginator("get_dev_endpoints")
            endpoints = []
            for page in paginator.paginate():
                endpoints.extend(page.get("DevEndpoints", []))
        except ClientError as e:
            code, reason = classify_error(e)
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": f"Could not list dev endpoints - {reason} ({code})",
            })
            continue

        for ep in endpoints:
            total_checked += 1
            name = ep.get("EndpointName", "N/A")
            arn = f"arn:aws:glue:{region}:{account_id}:devEndpoint/{name}"
            sec_config_name = ep.get("SecurityConfiguration")

            if not sec_config_name:
                non_compliant += 1
                results.append({
                    "Region": region, "ResourceId": name, "ResourceArn": arn,
                    "Status": "NON_COMPLIANT",
                    "Evidence": "No security configuration attached to endpoint",
                })
                continue

            try:
                sec_config = glue.get_security_configuration(
                    Name=sec_config_name
                )["SecurityConfiguration"]
            except ClientError as e:
                code, reason = classify_error(e)
                skipped += 1
                results.append({
                    "Region": region, "ResourceId": name, "ResourceArn": arn,
                    "Status": "SKIPPED",
                    "Evidence": f"Could not read security configuration '{sec_config_name}' - {reason} ({code})",
                })
                continue

            is_compliant, evidence = s3_encryption_status(sec_config)
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
    filename = f"glue_dev_endpoint_s3_encryption_{account_id}.csv"
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
