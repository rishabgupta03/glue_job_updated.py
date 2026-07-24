#!/usr/bin/env python3
"""
Control: Glue connection has SSL enabled.

Checks every Glue connection in every enabled region and verifies that SSL
enforcement is turned on, where applicable:
  - JDBC connections: ConnectionProperties.JDBC_ENFORCE_SSL == "true"
  - Kafka connections: ConnectionProperties.KAFKA_SSL_ENABLED == "true"

Other connection types (e.g. NETWORK, MONGODB, CUSTOM, MARKETPLACE) do not
expose a comparable SSL-enforcement property through the Glue connection
properties and are marked as not applicable.
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


SSL_PROPERTY_BY_TYPE = {
    "JDBC": "JDBC_ENFORCE_SSL",
    "KAFKA": "KAFKA_SSL_ENABLED",
}


def build_connection_arn(region, account_id, connection_name):
    return f"arn:aws:glue:{region}:{account_id}:connection/{connection_name}"


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
            paginator = glue.get_paginator("get_connections")
            connections = []
            for page in paginator.paginate(HidePassword=True):
                connections.extend(page.get("ConnectionList", []))
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            results.append({
                "Region": region,
                "ConnectionName": "N/A",
                "ConnectionArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        for conn in connections:
            conn_name = conn.get("Name", "N/A")
            conn_arn = build_connection_arn(region, account_id, conn_name)
            conn_type = conn.get("ConnectionType", "UNKNOWN")

            ssl_property_name = SSL_PROPERTY_BY_TYPE.get(conn_type)

            if not ssl_property_name:
                skipped += 1
                results.append({
                    "Region": region,
                    "ConnectionName": conn_name,
                    "ConnectionArn": conn_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"SSL enforcement is not applicable/configurable for connection type '{conn_type}'"
                })
                continue

            total_checked += 1
            properties = conn.get("ConnectionProperties", {})
            ssl_enabled = str(properties.get(ssl_property_name, "false")).lower() == "true"

            if ssl_enabled:
                status = "COMPLIANT"
                compliant += 1
                evidence = f"SSL is enabled ({ssl_property_name}=true)"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = f"SSL is not enabled ({ssl_property_name} is not set to true)"

            results.append({
                "Region": region,
                "ConnectionName": conn_name,
                "ConnectionArn": conn_arn,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"glue_connection_ssl_enabled_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ConnectionName", "ConnectionArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "ConnectionName": row["ConnectionName"],
                "ConnectionArn": row["ConnectionArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check Glue connections have SSL enabled where applicable."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "Glue - Connection Has SSL Enabled"

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
