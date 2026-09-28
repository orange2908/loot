---
title: "AWS CLI Cheatsheet - Enumeration After You Get Keys"
category: cloud
subcategory: aws
type: cheatsheet
tags: [cloud, aws, awscli, enumeration, sts, iam, s3, secretsmanager, ssm, lambda, ec2, dynamodb, kms, profiles, session-token, pacu, scoutsuite, prowler, get-caller-identity]
summary: "The AWS CLI commands that matter after obtaining credentials, per service, plus identity, profiles, session tokens and tooling pointers."
tools: [awscli, jq, pacu, scoutsuite, prowler]
related: [aws-enumeration-privesc, cloud-metadata-ssrf, object-storage-misconfig, serverless-attacks]
---

## Set up credentials

```bash
# temporary (metadata / STS) creds -- SESSION_TOKEN is required for ASIA... keys
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
export AWS_DEFAULT_REGION=us-east-1

# long-lived IAM user creds (AKIA...) -- no session token
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

# or a named profile in ~/.aws/credentials
aws configure --profile ctf
aws sts get-caller-identity --profile ctf

# use a profile per command
alias awsc='aws --profile ctf'

# skip signing entirely (anonymous access to public resources)
aws s3 ls s3://bucket --no-sign-request

# custom endpoint (localstack / minio / a CTF mock)
aws --endpoint-url http://localhost:4566 s3 ls
```

## Identity and context (do these first)

```bash
# who am I? account id + ARN (user vs assumed-role)
aws sts get-caller-identity
# decode a failed-authorization message
aws sts decode-authorization-message --encoded-message "$MSG"
# get a session token (MFA / temporary creds)
aws sts get-session-token --duration-seconds 3600
# assume a role you are trusted for
aws sts assume-role --role-arn arn:aws:iam::123:role/Target --role-session-name s
# list regions to know where to look
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
# the account alias
aws iam list-account-aliases
```

## IAM

```bash
# my user / roles / groups
aws iam get-user
aws iam list-users
aws iam list-roles
aws iam list-groups
# policies attached to a user / role
aws iam list-attached-user-policies --user-name NAME
aws iam list-user-policies --user-name NAME               # inline
aws iam get-user-policy --user-name NAME --policy-name P
aws iam list-attached-role-policies --role-name ROLE
aws iam list-role-policies --role-name ROLE
# read a managed policy document (need the default version id)
aws iam get-policy --policy-arn ARN
aws iam get-policy-version --policy-arn ARN --version-id v2
# a role's trust policy (who can assume it)
aws iam get-role --role-name ROLE --query 'Role.AssumeRolePolicyDocument'
# simulate what an action would resolve to (non-destructive)
aws iam simulate-principal-policy --policy-source-arn "$ARN" \
  --action-names s3:GetObject iam:PassRole
# access keys on a user
aws iam list-access-keys --user-name NAME
# instance profiles (link roles to EC2)
aws iam list-instance-profiles
```

## S3

```bash
# list all buckets I can see
aws s3 ls
aws s3api list-buckets --query 'Buckets[].Name' --output text
# list one bucket
aws s3 ls s3://bucket --recursive
aws s3api list-objects-v2 --bucket bucket --query 'Contents[].Key' --output text
# anonymous
aws s3 ls s3://bucket --no-sign-request
# read / download
aws s3 cp s3://bucket/key - 
aws s3 cp s3://bucket/key ./out --no-sign-request
aws s3 sync s3://bucket ./local
# bucket policy and ACL (exposure)
aws s3api get-bucket-policy --bucket bucket
aws s3api get-bucket-acl --bucket bucket
aws s3api get-public-access-block --bucket bucket
# old / deleted versions
aws s3api list-object-versions --bucket bucket --query 'Versions[].[Key,VersionId]' --output text
aws s3api get-object --bucket bucket --key k --version-id V out.txt
# encryption + location
aws s3api get-bucket-encryption --bucket bucket
aws s3api get-bucket-location --bucket bucket
```

## Secrets Manager & SSM Parameter Store

```bash
# secrets manager
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text
aws secretsmanager get-secret-value --secret-id NAME --query SecretString --output text
aws secretsmanager describe-secret --secret-id NAME
# ssm parameter store (SecureString values need --with-decryption)
aws ssm describe-parameters --query 'Parameters[].Name' --output text
aws ssm get-parameter --name /path/to/param --with-decryption --query Parameter.Value --output text
aws ssm get-parameters-by-path --path / --recursive --with-decryption
# run a command on an instance via SSM (if permitted)
aws ssm send-command --document-name AWS-RunShellScript \
  --targets Key=instanceids,Values=i-0abc --parameters 'commands=["id"]'
aws ssm start-session --target i-0abc
```

## Lambda

```bash
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,Role]' --output text
aws lambda get-function-configuration --function-name FN --query 'Environment.Variables'
aws lambda get-function --function-name FN --query Code.Location --output text   # source download URL
aws lambda get-function-url-config --function-name FN --query FunctionUrl --output text
aws lambda get-policy --function-name FN                                          # resource policy
aws lambda invoke --function-name FN --payload '{"k":"v"}' out.json
```

## EC2

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,PublicIpAddress,IamInstanceProfile.Arn,State.Name]' \
  --output table
# user data often contains bootstrap secrets
aws ec2 describe-instance-attribute --instance-id i-0abc --attribute userData \
  --query 'UserData.Value' --output text | base64 -d
aws ec2 describe-security-groups
aws ec2 describe-volumes
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-images --owners self
aws ec2 describe-key-pairs
# create a key + push to an instance you reach (privesc, if permitted)
aws ec2-instance-connect send-ssh-public-key --instance-id i-0abc \
  --instance-os-user ec2-user --ssh-public-key file://key.pub
```

## Other data stores

```bash
# DynamoDB
aws dynamodb list-tables
aws dynamodb scan --table-name T --max-items 25
aws dynamodb describe-table --table-name T
# RDS
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Endpoint.Address,MasterUsername]'
aws rds describe-db-snapshots
# KMS
aws kms list-keys
aws kms list-aliases
aws kms describe-key --key-id ARN
# ECR (container images)
aws ecr describe-repositories
aws ecr list-images --repository-name repo
aws ecr get-login-password | docker login --username AWS --password-stdin "$ACCT.dkr.ecr.$REGION.amazonaws.com"
# ECS
aws ecs list-clusters
aws ecs list-task-definitions
aws ecs describe-task-definition --task-definition td:1 --query 'taskDefinition.containerDefinitions[].environment'
```

## Logs, config and inventory

```bash
aws cloudtrail describe-trails
aws cloudtrail lookup-events --max-results 20
aws logs describe-log-groups
aws logs tail /aws/lambda/FN --since 1h
aws config describe-configuration-recorders
aws resourcegroupstaggingapi get-resources --query 'ResourceTagMappingList[].ResourceARN'
aws organizations list-accounts 2>/dev/null
```

## Output and query helpers

```bash
# JMESPath query + table/text/json output
aws s3api list-buckets --query 'Buckets[?starts_with(Name, `prod`)].Name' --output text
# pipe to jq for anything JMESPath cannot express
aws iam list-roles | jq -r '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS=="*") | .RoleName'
# page through large results
aws s3api list-objects-v2 --bucket b --max-items 100 --starting-token "$TOKEN"
# suppress the pager
export AWS_PAGER=""
```

## Tooling pointers

```bash
# Pacu -- AWS exploitation framework
pacu
#   import_keys --all
#   run iam__enum_permissions
#   run iam__privesc_scan
#   run s3__download_bucket

# enumerate-iam -- brute-force which API calls succeed
enumerate-iam --access-key AKIA... --secret-key ...

# ScoutSuite -- multi-cloud posture report (HTML)
scout aws --profile ctf

# Prowler -- CIS / best-practice checks
prowler aws -p ctf

# PMapper -- graph IAM escalation paths
pmapper --profile ctf graph create
pmapper --profile ctf query 'preset privesc *'

# CloudMapper / cartography -- visualise the account
```

## Common errors

```bash
# "The security token included in the request is invalid" -> ASIA key without AWS_SESSION_TOKEN
# "SignatureDoesNotMatch" -> wrong secret, or clock skew
# "AccessDenied" -> the call is not in your policy; try simulate-principal-policy or enumerate-iam
# "Could not connect to the endpoint URL" -> wrong region; set AWS_DEFAULT_REGION
# a 301 on S3 -> bucket is in another region; add --region
```
