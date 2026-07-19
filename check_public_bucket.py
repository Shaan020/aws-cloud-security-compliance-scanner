import boto3

s3 = boto3.client('s3')

def check_bucket_public(bucket_name):
    try:
        result = s3.get_public_access_block(Bucket=bucket_name)
        config = result['PublicAccessBlockConfiguration']
        if all(config.values()):
            return f"{bucket_name}: PASS - public access is blocked"
        else:
            return f"{bucket_name}: FAIL - public access is NOT fully blocked"
    except Exception as e:
        return f"{bucket_name}: ERROR - {e}"

response = s3.list_buckets()
for bucket in response['Buckets']:
    print(check_bucket_public(bucket['Name']))