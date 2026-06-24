#!/usr/bin/env python3
"""
Control     : Glue ETL job has continuous CloudWatch logging enabled
Description : For every enabled region, checks each AWS Glue job's
              DefaultArguments for "--enable-continuous-cloudwatch-log" set
              to "true". Unlike the S3/CloudWatch/bookmark encryption
              controls, this needs no Security Configuration lookup -
              DefaultArguments comes back on the same GetJobs call, so each
              job is evaluated with zero extra API calls.
"""

import argparse
import csv

import boto3
from boto3 import Session
from botocore.exceptions import BotoCoreError, ClientError
from tqdm import tqdm

CONTROL_NAME = "Glue ETL Job Has Continuous CloudWatch Logging Enabled"
LOGGING_ARG = "--enable-continuous-cloudwatch-log"


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


def continuous_logging_status(job: dict):
    """Returns (is_enabled: bool, detail: str) read straight from DefaultArguments."""
    value = (job.get("DefaultArguments") or {}).get(LOGGING_ARG)
    if value is None:
        return False, f"Continuous logging parameter ({LOGGING_ARG}) is not set"
    if str(value).strip().lower() == "true":
        return True, f"Continuous CloudWatch logging is enabled ({LOGGING_ARG}=true)"
    return False, f"Continuous logging parameter is set to '{value}', not 'true'"


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

        for job in jobs:
            job_name = job.get("Name", "N/A")
            job_arn = f"arn:aws:glue:{region}:{account_id}:job/{job_name}"

            total_checked += 1
            is_enabled, detail = continuous_logging_status(job)
            if is_enabled:
                compliant += 1
                status = "COMPLIANT"
            else:
                non_compliant += 1
                status = "NON_COMPLIANT"

            results.append({
                "Region": region, "ResourceId": job_name, "ResourceArn": job_arn,
                "Status": status, "Evidence": detail,
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"glue_etl_job_continuous_cloudwatch_logging_enabled_{account_id}.csv"
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