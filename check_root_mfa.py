import boto3

iam = boto3.client('iam')

def check_root_mfa():
    response = iam.get_account_summary()
    summary = response['SummaryMap']
    
    account_mfa_enabled = summary.get('AccountMFAEnabled')
    
    if account_mfa_enabled == 1:
        print("ROOT ACCOUNT: PASS - MFA is enabled on root")
    else:
        print("ROOT ACCOUNT: FAIL - MFA is NOT enabled on root - CRITICAL RISK")

check_root_mfa()
