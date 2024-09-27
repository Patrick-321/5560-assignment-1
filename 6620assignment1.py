import boto3
import json
import logging
from botocore.client import ClientError

# Setting up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS Clients Setup
client_iam, client_sts = boto3.client('iam'), boto3.client('sts')

# Configuration Constants
REGION = 'us-east-1'
BUCKET_NAME = 'lecture1'
IAM_USER_NAME = 'patrick1'


# Helper Function to Get Account ID
def get_id():
    return client_sts.get_caller_identity()['Account']


# Create IAM Roles and Attach Policies
def create_iam_roles(role_name, policy_arn, trust_user_arn=None):
    try:
        role = client_iam.get_role(RoleName=role_name)
        logger.info(f"Role {role_name} already exists. Skipping creation.")
        return role['Role']['Arn']
    except ClientError as client:
        if client.response['Error']['Code'] == 'NoSuchEntity':
            logger.info(f"Creating role {role_name}")
            assume_role_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": trust_user_arn} if trust_user_arn else {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            role = client_iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy)
            )

            client_iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            return role['Role']['Arn']
        else:
            logger.error(f"Failed to create role {role_name}: {client}")
            raise


# Function to Attach Policies to Roles
def policy_roles():
    account_id = get_id()
    user_arn = f"arn:aws:iam::{account_id}:user/{IAM_USER_NAME}"
    create_iam_roles('Dev', 'arn:aws:iam::aws:policy/AmazonS3FullAccess', trust_user_arn=user_arn)
    create_iam_roles('User', 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess', trust_user_arn=user_arn)


# Function to Create IAM User and Attach Inline Policy
def create_iam_user(username):
    try:
        user = client_iam.get_user(UserName=username)
        logger.info(f"IAM User {username} already exists. Skipping creation.")
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            client_iam.create_user(UserName=username)
            logger.info(f"IAM User {username} created successfully")

    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }
        ]
    }

    try:
        client_iam.put_user_policy(
            UserName=username,
            PolicyName='AssumeUserRolePolicy',
            PolicyDocument=json.dumps(assume_role_policy)
        )
        logger.info(f'Policy AssumeUserRolePolicy attached to user {username}')
    except ClientError as error:
        logger.error(f'Failed to attach policy to user {username}: {error}')
        raise


# Function to Assume Role
def assume_role(role_name, session_name):
    account_id = get_id()
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    assumed_role = client_sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    credentials = assumed_role['Credentials']
    return boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=REGION
    )


# Function to Upload Files to S3 Bucket
def upload_files_to_bucket(s3_client):
    files = {
        'assignment1.txt': 'Empty Assignment 1',
        'assignment2.txt': 'Empty Assignment 2',
        'prince_garden.jpeg': None  # Image file name
    }

    for key, body in files.items():
        if body:
            s3_client.put_object(Bucket=BUCKET_NAME, Key=key, Body=body)
            logger.info(f'{key} uploaded successfully')
        else:
            with open(key, 'rb') as img_file:
                s3_client.put_object(Bucket=BUCKET_NAME, Key=key, Body=img_file)
            logger.info(f'{key} uploaded successfully')


# Function to Create S3 Bucket and Upload Files
def dev_role_and_create_s3_resources():
    s3_client = assume_role('Dev', 'AssumeDevRoleSession')

    # Handle bucket creation with existence check
    try:
        s3_client.create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
        logger.info(f'S3 bucket {BUCKET_NAME} successfully created')
    except ClientError as error:
        if error.response['Error']['Code'] in ['BucketAlreadyExists', 'BucketAlreadyOwnedByYou']:
            logger.info(f"S3 bucket {BUCKET_NAME} already exists. Skipping creation.")
        else:
            logger.error(f"Failed to create bucket {BUCKET_NAME}: {error}")
            raise

    upload_files_to_bucket(s3_client)


# Function to Calculate Total Size of Objects in S3 Bucket
def user_role_and_calculate_objects_size():
    s3_client = assume_role('User', 'AssumeUserRoleSession')

    try:
        objects = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
        total_size = sum(obj['Size'] for obj in objects.get('Contents', []))
        logger.info(f"Total size of objects in {BUCKET_NAME}: {total_size} bytes")
    except ClientError as e:
        logger.error(f"Failed to list objects in bucket {BUCKET_NAME}: {e}")
        raise


# Function to Delete All Objects in S3 Bucket
def dev_role_and_delete_objects():
    s3_client = assume_role('Dev', 'AssumeDevRoleSession')

    try:
        objects = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
        for obj in objects.get('Contents', []):
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=obj['Key'])
            logger.info(f"Object {obj['Key']} deleted successfully")
    except ClientError as error:
        logger.error(f"Failed to delete objects in bucket {BUCKET_NAME}: {error}")
        raise


# Main Function
if __name__ == '__main__':
    policy_roles()
    create_iam_user(IAM_USER_NAME)
    dev_role_and_create_s3_resources()
    user_role_and_calculate_objects_size()
    dev_role_and_delete_objects()
