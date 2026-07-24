#!/usr/bin/env python3
"""
Control: Glue Data Catalog metadata is encrypted with KMS.

Checks the Data Catalog encryption-at-rest setting in every enabled region
and verifies that CatalogEncryptionMode is set to SSE-KMS (or
SSE-KMS-WITH-SERVICE-ROLE) with a KMS key configured. This is a region-wide
Data Catalog setting - it protects all database and table metadata in that
account/region, not an individual per-resource field, so this control is
evaluated once per region rather than per Glue resource.
"""

import boto3
import argparse
import csv
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


COMPLIANT_MODES = {"SSE-KMS", "SSE-KMS-WITH-SERVICE-ROLE"}


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
            settings = glue.get_data_catalog_encryption_settings().get(
                "DataCatalogEncryptionSettings", {}
            )
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            total_checked -= 1
            results.append({
                "Region": region,
                "ResourceArn": catalog_arn,
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        encryption_at_rest = settings.get("EncryptionAtRest", {})
        encryption_mode = encryption_at_rest.get("CatalogEncryptionMode", "DISABLED")
        kms_key_id = encryption_at_rest.get("SseAwsKmsKeyId")

        if encryption_mode in COMPLIANT_MODES and kms_key_id:
            status = "COMPLIANT"
            compliant += 1
            evidence = f"Metadata encryption is enabled (mode: {encryption_mode}, KMS key: {kms_key_id})"
        elif encryption_mode in COMPLIANT_MODES and not kms_key_id:
            status = "NON_COMPLIANT"
            non_compliant += 1
            evidence = f"Encryption mode is '{encryption_mode}' but no KMS key is configured"
        else:
            status = "NON_COMPLIANT"
            non_compliant += 1
            evidence = f"Metadata encryption is disabled (mode: {encryption_mode})"

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
    filename = f"glue_catalog_metadata_kms_encryption_{account_id}_{timestamp}.csv"

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
        description="Check Glue Data Catalog metadata is encrypted with KMS."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "Glue - Data Catalog Metadata Encrypted With KMS"

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
