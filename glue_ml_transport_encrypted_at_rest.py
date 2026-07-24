#!/usr/bin/env python3
"""
Control      : Glue ML Transform is encrypted at rest
Service      : AWS Glue (regional service)
Logic        : For every Glue ML Transform, inspect TransformEncryption.
               MlUserDataEncryption governs at-rest encryption of the
               transform's training/user data (mode is DISABLED or SSE-KMS).
               A transform is only COMPLIANT when that mode is SSE-KMS.
               TaskRunSecurityConfigurationName (if present) is surfaced in
               evidence for context but does not by itself satisfy the control,
               since it governs task-run S3 output, not the transform's own
               user-data encryption.
"""

import argparse
import csv
import boto3
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "Glue ML Transform - Encrypted at Rest"

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


def ml_transform_encryption_status(transform):
    """
    Given an MLTransform dict, return (is_compliant, evidence).
    Compliant only when MlUserDataEncryptionMode == 'SSE-KMS'.
    """
    encryption = transform.get("TransformEncryption", {})
    ml_data_enc = encryption.get("MlUserDataEncryption", {})
    mode = ml_data_enc.get("MlUserDataEncryptionMode", "DISABLED")
    task_run_sec_config = encryption.get("TaskRunSecurityConfigurationName")

    if mode == "SSE-KMS":
        kms_key = ml_data_enc.get("KmsKeyId", "default AWS managed key")
        evidence = f"MlUserDataEncryption mode SSE-KMS (KmsKeyId: {kms_key})"
        if task_run_sec_config:
            evidence += f"; TaskRunSecurityConfiguration: {task_run_sec_config}"
        return True, evidence

    evidence = "MlUserDataEncryption mode is DISABLED - user data not encrypted at rest"
    if task_run_sec_config:
        evidence += f" (TaskRunSecurityConfiguration '{task_run_sec_config}' set, but does not cover user data encryption)"
    return False, evidence


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
            paginator = glue.get_paginator("get_ml_transforms")
            transforms = []
            for page in paginator.paginate():
                transforms.extend(page.get("Transforms", []))
        except ClientError as e:
            code, reason = classify_error(e)
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": f"Could not list ML transforms - {reason} ({code})",
            })
            continue

        for transform in transforms:
            total_checked += 1
            transform_id = transform.get("TransformId", "N/A")
            name = transform.get("Name", transform_id)
            arn = f"arn:aws:glue:{region}:{account_id}:mlTransform/{transform_id}"

            is_compliant, evidence = ml_transform_encryption_status(transform)
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
    filename = f"glue_ml_transform_encrypted_at_rest_{account_id}.csv"
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
