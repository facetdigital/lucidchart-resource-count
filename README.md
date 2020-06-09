# LucidChart Resource Count

This is a simple Docker wrapper for running the [LucidChart Cloud Insights Resource Count Script](https://lucidchart.zendesk.com/hc/en-us/articles/360038696972-Lucidchart-Cloud-Insights-Resource-Count-Script) in order to count the number of resources that are in scope for LucidChart's Cloud Insights to import into a diagram.

**_Currently only works with AWS, and only tested on macOS. Requires Docker._**

Using this script allows you to run LucidChart's script w/o installing Python or `botocore` on your machine.

_The core python script was snapshotted from LucidChart [here](https://lucidchart.zendesk.com/hc/article_attachments/360047954071/aws_cli_script.py)._

## Quick Start

* [Install Docker](https://docs.docker.com/get-docker/) if you have not already. Make sure it is running.
* [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) if you don't have it already.

* Create an IAM account in AWS that has read-only access to the things LucidChart can access and grab its Access Key Id and Secret. The policy for this can look something like this:

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "apigateway:GET",
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:DescribeLaunchConfigurations",
                    "cloudfront:ListDistributions",
                    "cloudfront:ListTagsForResource",
                    "dynamodb:DescribeTable",
                    "dynamodb:ListTables",
                    "dynamodb:ListTagsOfResource",
                    "ec2:DescribeInstances",
                    "ec2:DescribeInternetGateways",
                    "ec2:DescribeNatGateways",
                    "ec2:DescribeNetworkAcls",
                    "ec2:DescribeRouteTables",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeTransitGateways",
                    "ec2:DescribeTransitGatewayPeeringAttachments",
                    "ec2:DescribeTransitGatewayRouteTables",
                    "ec2:DescribeTransitGatewayVpcAttachments",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeVpcEndpoints",
                    "ec2:DescribeVpcEndpointConnections",
                    "ec2:DescribeVpnGateways",
                    "ec2:DescribeVpcPeeringConnections",
                    "elasticloadbalancing:DescribeLoadBalancers",
                    "elasticloadbalancing:DescribeTags",
                    "elasticloadbalancing:DescribeTargetGroups",
                    "elasticloadbalancing:DescribeTargetHealth",
                    "iam:GetGroupPolicy",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:GetRolePolicy",
                    "iam:GetUserPolicy",
                    "iam:ListAttachedGroupPolicies",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListGroupPolicies",
                    "iam:ListGroups",
                    "iam:ListGroupsForUser",
                    "iam:ListRolePolicies",
                    "iam:ListRoles",
                    "iam:ListUserPolicies",
                    "iam:ListUsers",
                    "lambda:ListFunctions",
                    "redshift:DescribeClusters",
                    "rds:DescribeDBClusters",
                    "rds:DescribeDBInstances",
                    "rds:ListTagsForResource",
                    "route53:ListHostedZones",
                    "route53:ListResourceRecordSets",
                    "route53:ListTagsForResource",
                    "s3:GetBucketLocation",
                    "s3:GetBucketTagging",
                    "s3:ListAllMyBuckets",
                    "sns:GetTopicAttributes",
                    "sns:ListTopics",
                    "sns:ListTagsForResource",
                    "sqs:GetQueueAttributes",
                    "sqs:ListQueues",
                    "sts:GetCallerIdentity"
                ],
                "Resource": [
                    "*"
                ]
            }
        ]
    }
   ```

* Configure a named AWS profile with the CLI, e.g.:

    ```bash
    aws configure --profile lucid
    ```

* Clone this repo, and build the docker container from its root directory:

    ```bash
    git clone git@github.com:facetdigital/lucidchart-resource-count.git
    cd lucidchart-resource-count
    ./run setup
    ```

* Run the script using the same parameters they document [here](https://lucidchart.zendesk.com/hc/en-us/articles/360038696972-Lucidchart-Cloud-Insights-Resource-Count-Script) using the `./run count` command. E.g.:

    ```bash
    ./run count --profile lucid --regions us-east-1 us-west-2 -c
    ```

* View your results in `count.json`
    
