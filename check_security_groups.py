import boto3

ec2 = boto3.client('ec2', region_name='eu-north-1')

RISKY_PORTS = [22, 3389]  

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
                    print(f"{sg_name} ({sg_id}): FAIL - port {from_port} open to entire internet")
                elif cidr == '0.0.0.0/0':
                    print(f"{sg_name} ({sg_id}): WARNING - port {from_port} open to internet (not in risky list, but still worth reviewing)")

check_security_groups()

print("Check complete.")