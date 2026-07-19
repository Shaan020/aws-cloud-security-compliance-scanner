import boto3

ec2 = boto3.client('ec2', region_name='eu-north-1')
response = ec2.describe_security_groups()

for sg in response['SecurityGroups']:
    print("Found SG:", sg['GroupName'], sg['GroupId'])
    print("Rules:", sg['IpPermissions'])
    print("---")