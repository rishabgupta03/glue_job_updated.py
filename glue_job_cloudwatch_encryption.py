#!/usr/bin/env python3
"""
Control     : Glue ETL job has CloudWatch Logs encryption enabled
Description : For every enabled region, checks each AWS Glue job's attached
              Security Configuration. A job is compliant only if it has a
              Security Configuration attached AND that configuration's
              CloudWatch Logs encryption mode is SSE-KMS (not DISABLED, and
              not missing). Security configurations are cached per region as
              a generic EncryptionConfiguration dict - many jobs share the
              same one, and caching the whole dict (rather than just the
              CloudWatch field) means the same cache can answer S3 or job
              bookmark encryption questions too without extra API calls.
"""

import argparse
import csv

import boto3
from boto3 import Session
from botocore.exceptions import BotoCoreError, ClientError
from tqdm import tqdm

CONTROL_NAME = "Glue ETL Job Has CloudWatch Logs Encryption Enabled"


# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None) -> Session:
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="control-audit")
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()


def get_account_id(session: Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session: Session) -> list:
    """All opted-in regions enabled for this account."""
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    ]


def get_service_regions(session: Session, service_name: str) -> list:
    """Enabled regions intersected with regions boto3 knows the service has endpoints in."""
    enabled = set(get_regions(session))
    supported = set(session.get_available_regions(service_name))
    return sorted(enabled & supported)


# ==================================================
# HELPERS
# ==================================================
def explain_error(e: Exception, action: str = "") -> str:
    """
    Short, human-readable reason for a skip - names the exact API action that
    failed so a denial is debuggable straight from the CSV, no guessing needed.
    """
    where = f" calling {action}" if action else ""
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "ClientError")
        if code in ("AccessDeniedException", "UnauthorizedException", "AccessDenied"):
            return f"Access denied - missing IAM permission for {action or 'this call'}"
        return f"AWS error{where}: {code}"
    if isinstance(e, BotoCoreError):
        return f"Client/connection error{where}: {e.__class__.__name__}"
    return f"Unexpected error{where}: {e.__class__.__name__}: {e}"


def list_glue_jobs(glue_client) -> list:
    """Manual NextToken pagination - avoids depending on a botocore paginator existing."""
    jobs, next_token = [], None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        response = glue_client.get_jobs(**kwargs)
        jobs.extend(response.get("Jobs", []))
        next_token = response.get("NextToken")
        if not next_token:
            return jobs


def get_encryption_config(glue_client, config_name: str, cache: dict) -> dict:
    """
    Fetches and caches a Security Configuration's full EncryptionConfiguration
    dict per region. Generic on purpose - whichever encryption field a given
    control cares about (S3, CloudWatch, job bookmarks) is read out of the
    same cached dict, so jobs sharing a configuration only cost one API call.
    """
    if config_name not in cache:
        response = glue_client.get_security_configuration(Name=config_name)
        cache[config_name] = response.get("SecurityConfiguration", {}).get("EncryptionConfiguration", {})
    return cache[config_name]


def cloudwatch_encryption_status(encryption_config: dict):
    """Returns (is_encrypted: bool, detail: str) for the CloudWatch Logs encryption field."""
    mode = encryption_config.get("CloudWatchEncryption", {}).get("CloudWatchEncryptionMode", "DISABLED")
    if mode != "DISABLED":
        return True, f"CloudWatch Logs encryption mode: {mode}"
    return False, "Security configuration exists but CloudWatch Logs encryption mode is DISABLED"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session: Session):
    account_id = get_account_id(session)
    regions = get_service_regions(session, "glue")

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to scan : {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning regions"):
        try:
            glue = session.client("glue", region_name=region)
        except (ClientError, BotoCoreError) as e:
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": explain_error(e, "boto3 client creation"),
            })
            continue

        try:
            jobs = list_glue_jobs(glue)
        except (ClientError, BotoCoreError) as e:
            skipped += 1
            results.append({
                "Region": region, "ResourceId": "N/A", "ResourceArn": "N/A",
                "Status": "SKIPPED", "Evidence": explain_error(e, "glue:GetJobs"),
            })
            continue

        encryption_cache = {}

        for job in jobs:
            job_name = job.get("Name", "N/A")
            job_arn = f"arn:aws:glue:{region}:{account_id}:job/{job_name}"
            config_name = job.get("SecurityConfiguration")

            if not config_name:
                total_checked += 1
                non_compliant += 1
                results.append({
                    "Region": region, "ResourceId": job_name, "ResourceArn": job_arn,
                    "Status": "NON_COMPLIANT",
                    "Evidence": "No Security Configuration attached to this job",
                })
                continue

            try:
                encryption_config = get_encryption_config(glue, config_name, encryption_cache)
                is_encrypted, detail = cloudwatch_encryption_status(encryption_config)
                total_checked += 1
                if is_encrypted:
                    compliant += 1
                    status, evidence = "COMPLIANT", f"Security configuration '{config_name}' - {detail}"
                else:
                    non_compliant += 1
                    status, evidence = "NON_COMPLIANT", f"Security configuration '{config_name}' - {detail}"

            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "EntityNotFoundException":
                    # The job points at a security config that no longer exists - encryption
                    # is not actually being enforced, so this is a real finding, not a skip.
                    total_checked += 1
                    non_compliant += 1
                    status = "NON_COMPLIANT"
                    evidence = f"Job references Security Configuration '{config_name}' which does not exist"
                else:
                    skipped += 1
                    status = "SKIPPED"
                    evidence = explain_error(e, "glue:GetSecurityConfiguration")
            except BotoCoreError as e:
                skipped += 1
                status = "SKIPPED"
                evidence = explain_error(e, "glue:GetSecurityConfiguration")

            results.append({
                "Region": region, "ResourceId": job_name, "ResourceArn": job_arn,
                "Status": status, "Evidence": evidence,
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"glue_etl_job_cloudwatch_logs_encryption_enabled_{account_id}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"],
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
    parser.add_argument("-R", "--role-arn", help="IAM role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    print("=" * 60)
    print(f"CONTROL : {CONTROL_NAME}")
    print(f"ACCOUNT : {account_id}")
    print("=" * 60)

    results, total_checked, compliant, non_compliant, skipped = check_control(session)
    if total_checked == 0 and skipped > 0:
        overall = "INCONCLUSIVE - all resources skipped, see CSV Evidence column"
    elif non_compliant > 0:
        overall = "NON_COMPLIANT"
    else:
        overall = "COMPLIANT"
    csv_file = write_csv(results, account_id)

    print("=" * 60)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()