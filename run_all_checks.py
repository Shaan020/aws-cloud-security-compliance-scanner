import boto3
import json
from datetime import datetime, timezone

# ===== SETUP =====
s3 = boto3.client('s3')
iam = boto3.client('iam')
ec2 = boto3.client('ec2', region_name='eu-north-1')

RISKY_PORTS = [22, 3389]
MAX_KEY_AGE_DAYS = 90

all_results = []  # this will hold every finding from every check

# ===== CHECK 1: S3 Public Access =====
def check_s3_public_access():
    response = s3.list_buckets()
    for bucket in response['Buckets']:
        name = bucket['Name']
        try:
            result = s3.get_public_access_block(Bucket=name)
            config = result['PublicAccessBlockConfiguration']
            if all(config.values()):
                status = "PASS"
                message = "Public access is blocked"
            else:
                status = "FAIL"
                message = "Public access is NOT fully blocked"
        except Exception as e:
            status = "ERROR"
            message = str(e)

        all_results.append({
            "check": "S3 Public Access",
            "resource": name,
            "status": status,
            "message": message
        })

# ===== CHECK 2: IAM User MFA =====
def check_iam_mfa():
    users_response = iam.list_users()
    for user in users_response['Users']:
        username = user['UserName']
        response = iam.list_mfa_devices(UserName=username)

        if len(response['MFADevices']) == 0:
            status = "FAIL"
            message = "No MFA device enabled"
        else:
            status = "PASS"
            message = "MFA is enabled"

        all_results.append({
            "check": "IAM User MFA",
            "resource": username,
            "status": status,
            "message": message
        })

# ===== CHECK 3: Security Groups =====
def check_security_groups():
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']

        for rule in sg['IpPermissions']:
            from_port = rule.get('FromPort')
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')

                if cidr == '0.0.0.0/0' and from_port in RISKY_PORTS:
                    all_results.append({
                        "check": "Security Group Exposure",
                        "resource": f"{sg_name} ({sg_id})",
                        "status": "FAIL",
                        "message": f"Port {from_port} open to entire internet"
                    })
                elif cidr == '0.0.0.0/0':
                    all_results.append({
                        "check": "Security Group Exposure",
                        "resource": f"{sg_name} ({sg_id})",
                        "status": "WARNING",
                        "message": f"Port {from_port} open to internet"
                    })

# ===== CHECK 4: Old Access Keys =====
def check_old_access_keys():
    users_response = iam.list_users()
    for user in users_response['Users']:
        username = user['UserName']
        response = iam.list_access_keys(UserName=username)

        if len(response['AccessKeyMetadata']) == 0:
            all_results.append({
                "check": "Access Key Age",
                "resource": username,
                "status": "INFO",
                "message": "No access keys found"
            })
            continue

        for key in response['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            created_date = key['CreateDate']
            age_days = (datetime.now(timezone.utc) - created_date).days

            if age_days > MAX_KEY_AGE_DAYS:
                status = "FAIL"
                message = f"Key is {age_days} days old (limit: {MAX_KEY_AGE_DAYS})"
            else:
                status = "PASS"
                message = f"Key is {age_days} days old"

            all_results.append({
                "check": "Access Key Age",
                "resource": f"{username} - {key_id}",
                "status": status,
                "message": message
            })

# ===== CHECK 5: Root Account MFA =====
def check_root_mfa():
    response = iam.get_account_summary()
    summary = response['SummaryMap']
    account_mfa_enabled = summary.get('AccountMFAEnabled')

    if account_mfa_enabled == 1:
        status = "PASS"
        message = "MFA is enabled on root"
    else:
        status = "FAIL"
        message = "MFA is NOT enabled on root - CRITICAL RISK"

    all_results.append({
        "check": "Root Account MFA",
        "resource": "root",
        "status": status,
        "message": message
    })

# ===== RUN EVERYTHING =====
print("Running all checks...")
check_s3_public_access()
check_iam_mfa()
check_security_groups()
check_old_access_keys()
check_root_mfa()

# ===== SAVE RESULTS TO JSON =====
with open('scan_results.json', 'w') as f:
    json.dump(all_results, f, indent=2)

print(f"Done. {len(all_results)} findings saved to scan_results.json")