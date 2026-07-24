#!/usr/bin/env python3
"""
Control: Glue development endpoint has CloudWatch Logs encryption enabled.

CloudWatch Logs encryption for a Glue development endpoint is not a direct
field on the endpoint itself - it comes from a Glue Security Configuration
attached to it (SecurityConfiguration name), which defines
EncryptionConfiguration.CloudWatchEncryption.

Checks every Glue development endpoint in every enabled region:
  - No Security Configuration attached at all -> non-compliant (no
    CloudWatch Logs encryption is possible without one).
  - Security Configuration attached -> fetched and checked for
    CloudWatchEncryption.CloudWatchEncryptionMode == "SSE-KMS" with a KMS
    key configured.
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


def build_endpoint_arn(region, account_id, endpoint_name):
    return f"arn:aws:glue:{region}:{account_id}:devEndpoint/{endpoint_name}"


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
            paginator = glue.get_paginator("get_dev_endpoints")
            endpoints = []
            for page in paginator.paginate():
                endpoints.extend(page.get("DevEndpoints", []))
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            results.append({
                "Region": region,
                "EndpointName": "N/A",
                "EndpointArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        # Cache security configuration lookups within the region to avoid
        # re-fetching the same one for multiple endpoints that share it.
        security_config_cache = {}

        for endpoint in endpoints:
            total_checked += 1
            endpoint_name = endpoint.get("EndpointName", "N/A")
            endpoint_arn = build_endpoint_arn(region, account_id, endpoint_name)
            security_config_name = endpoint.get("SecurityConfiguration")

            if not security_config_name:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = "No Security Configuration attached - CloudWatch Logs encryption is not possible"
                results.append({
                    "Region": region,
                    "EndpointName": endpoint_name,
                    "EndpointArn": endpoint_arn,
                    "Status": status,
                    "Evidence": evidence
                })
                continue

            if security_config_name not in security_config_cache:
                try:
                    sc_detail = glue.get_security_configuration(
                        Name=security_config_name
                    )["SecurityConfiguration"]
                    security_config_cache[security_config_name] = sc_detail
                except ClientError as e:
                    code, evidence = error_evidence(e)
                    security_config_cache[security_config_name] = None
                    skipped += 1
                    total_checked -= 1
                    results.append({
                        "Region": region,
                        "EndpointName": endpoint_name,
                        "EndpointArn": endpoint_arn,
                        "Status": "SKIPPED",
                        "Evidence": f"Could not retrieve Security Configuration '{security_config_name}': {evidence}"
                    })
                    continue

            sc_detail = security_config_cache.get(security_config_name)
            if sc_detail is None:
                skipped += 1
                total_checked -= 1
                results.append({
                    "Region": region,
                    "EndpointName": endpoint_name,
                    "EndpointArn": endpoint_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"Could not retrieve Security Configuration '{security_config_name}'"
                })
                continue

            cw_encryption = sc_detail.get("EncryptionConfiguration", {}).get("CloudWatchEncryption", {})
            cw_mode = cw_encryption.get("CloudWatchEncryptionMode", "DISABLED")
            kms_key_arn = cw_encryption.get("KmsKeyArn")

            if cw_mode == "SSE-KMS" and kms_key_arn:
                status = "COMPLIANT"
                compliant += 1
                evidence = f"CloudWatch Logs encryption is enabled (Security Configuration: {security_config_name}, KMS key: {kms_key_arn})"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = (
                    f"CloudWatch Logs encryption is not enabled "
                    f"(Security Configuration: {security_config_name}, mode: {cw_mode})"
                )

            results.append({
                "Region": region,
                "EndpointName": endpoint_name,
                "EndpointArn": endpoint_arn,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"glue_devendpoint_cloudwatch_encryption_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "EndpointName", "EndpointArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "EndpointName": row["EndpointName"],
                "EndpointArn": row["EndpointArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check Glue development endpoints have CloudWatch Logs encryption enabled."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "Glue - Development Endpoint CloudWatch Logs Encryption Enabled"

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
