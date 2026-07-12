import boto3

def get_iam_client():
    """
    Create and return an IAM client.
    boto3 automatically uses the credentials
    configured with 'aws configure'.
    """
    return boto3.client("iam")