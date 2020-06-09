#!/usr/bin/env python
import botocore.session
from datetime import datetime, tzinfo, timedelta
from argparse import ArgumentParser
import json
from os import environ
import sys
import hashlib

requiredBotocoreVersion = "1.13.0"
usage = "Usage: python importscript.py --profile <profile_name> --regions <region_name> [... --profile <profile_name> --regions <region_name_1> <region_name_2>] [-c]"

ERRORS = []
COUNT = False

class SimpleUtc(tzinfo):
    def tzname(self):
        return "UTC"

    def utcoffset(self, dt):
        return timedelta(0)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.utcnow().replace(tzinfo=SimpleUtc()).isoformat()

        return json.JSONEncoder.default(self, o)


class AwsImportTarget:
    def __init__(self, profile_name, region):
        self.profile_name = profile_name
        self.region = region


def chunk_list(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]

def flatten_list(l):
    return [item for sublist in l for item in sublist]

def encrypt_string(raw_string):
    return hashlib.sha256(raw_string.encode()).hexdigest()

def handle_error(target_info, e, name=''):
    errorMessage = 'Error: {account}:{region}:{name} {errorMessage}'.format(
        account=target_info.profile_name, region=target_info.region, name=name, errorMessage=str(e))
    ERRORS.append(errorMessage)
    print(errorMessage)


def make_request(request_fn, target_info, resourceName, key, abort_on_error = False):
    try:
        print('Executing {account}:{region}:{resourceName}'.format(
            account=target_info.profile_name, region=target_info.region, resourceName=resourceName))
        result = request_fn()
        return result.get(key, [])
    except Exception as e:
        handle_error(target_info, e, resourceName)
        if COUNT and abort_on_error:
            print('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []


def get_cloudfront_distributions(client, target_info):
    try:
        print('Executing {account}:{region}:cloudfront:list_distributions'.format(
            account=target_info.profile_name, region=target_info.region))
        result = client.list_distributions().get(
            'DistributionList', {}).get('Items', [])
        return result
    except Exception as e:
        handle_error(target_info, e, 'cloudfront:list_distributions:')
        return []


def get_lambda_functions(client, target_info):
    try:
        print('Executing {account}:{region}:lambda:list_functions'.format(
            account=target_info.profile_name, region=target_info.region))
        result = client.list_functions()['Functions']
        for lambdaFunction in result:
            if 'Environment' in lambdaFunction:
                del lambdaFunction['Environment']

        return result
    except Exception as e:
        handle_error(target_info, e, 'lambda:list_functions:')
        if COUNT:
            print('Unable to count resources because of error requesting required resources')
            exit()
        else:
            return []


def get_elb2_target_health(client, targetGroups, target_info):
    try:
        print('Executing {account}:{region}:elbv2:describe_target_health'.format(
            account=target_info.profile_name, region=target_info.region))
        response = []
        for target_group_arn in [target_group['TargetGroupArn'] for target_group in targetGroups]:
            response.extend(client.describe_target_health(
                TargetGroupArn=target_group_arn)['TargetHealthDescriptions'])

        return response
    except Exception as e:
        handle_error(target_info, e, 'elbv2:describe_target_health:')
        return []


def get_sns_topics(client, topics, target_info):
    try:
        result = []
        for t in topics:
            attrs = client.get_topic_attributes(TopicArn=t['TopicArn'])
            result.append({
                'Attributes': attrs['Attributes'],
                'TopicArn': t['TopicArn'],
            })
        return result
    except Exception as e:
        handle_error(target_info, e, 'sns:get_topic_attributes:')
        return []


sqsQueueAttributeWhitelist = {
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesDelayed",
    "ApproximateNumberOfMessagesNotVisible",
    "CreatedTimestamp",
    "DelaySeconds",
    "LastModifiedTimestamp",
    "MaximumMessageSize",
    "MessageRetentionPeriod",
    "Policy",
    "QueueArn",
    "ReceiveMessageWaitTimeSeconds",
    "RedrivePolicy",
    "VisibilityTimeout",
    "KmsMasterKeyId",
    "KmsDataKeyReusePeriodSeconds",
    "FifoQueue",
    "ContentBasedDeduplication"
}

def get_sqs_queues(client, queueUrls, target_info):
    try:
        result = []
        for url in queueUrls:
            attrs = client.get_queue_attributes(AttributeNames=['All'], QueueUrl=url)
            whitelistedAttributes = {key: value for (key,value) in attrs.items() if key in sqsQueueAttributeWhitelist}
            result.append({
                'Attributes': whitelistedAttributes,
                'QueueUrl': url,
            })
        return result
    except Exception as e:
        handle_error(target_info, e, 'sqs:get_queue_attributes:')
        return []


def get_dynamoDB_tables(client, tableNames, target_info):
    try:
        response = [client.describe_table(
            TableName=tableName)['Table'] for tableName in tableNames]
        return response
    except Exception as e:
        handle_error(target_info, e, 'dynamodb:describe_table')
        return []

def filter_s3_buckets_to_target_region(client, buckets, target_info):
    try:
        result = []
        for bucket in buckets:
            attrs = client.get_bucket_location(Bucket=bucket['Name'])
            region = attrs['LocationConstraint']
            if region == None:
                region = 'us-east-1'
            if region == target_info.region:
                result.append(bucket)
        return result
    except Exception as e:
        handle_error(target_info, e, 's3:get_bucket_location:')
        return []

def get_complete_albs(client, albs, targetGroups):
    albsResult = []
    targetGroupsResult = []

    resourceArns = []
    arnToTypeMap = {}
    arnToObjMap = {}
    for alb in albs:
        arn = alb['LoadBalancerArn']
        resourceArns.append(arn)
        arnToTypeMap[arn] = 'alb'
        arnToObjMap[arn] = alb
    for group in targetGroups:
        arn = group['TargetGroupArn']
        resourceArns.append(arn)
        arnToTypeMap[arn] = 'group'
        arnToObjMap[arn] = group

    tagInfoForAllResources = []
    try:
        chunkedListOfArns = chunk_list(resourceArns, 20)
        listOfTagLists = [client.describe_tags(ResourceArns=l)['TagDescriptions'] for l in chunkedListOfArns]
        tagInfoForAllResources = flatten_list(listOfTagLists)
    except Exception as e:
        print('Error fetching tag info for albs and target groups.\nError: {error}'.format(error=str(e)))

    for tagInfo in tagInfoForAllResources:
        arn = tagInfo['ResourceArn']
        del tagInfo['ResourceArn']
        obj = arnToObjMap.get(arn).copy()
        obj.update(tagInfo)
        resourceType = arnToTypeMap.get(arn)
        if resourceType == 'alb':
            albsResult.append(obj)
        elif resourceType == 'group':
            targetGroupsResult.append(obj)

    return albsResult, targetGroupsResult

def get_complete_cloudfront_distribution(client, distribution):
    result = distribution.copy()
    try:
        tagInfo = client.list_tags_for_resource(Resource=distribution['ARN'])
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except Exception as e:
        print('Error fetching tag info for distribution "{name}".\nError: {error}'.format(name=distribution['ARN'], error=str(e)))
        result['Tags'] = {
            'Items': []
        }
    return result

def get_complete_dynamodb_table(client, table):
    result = table.copy()
    try:
        paginator = client.get_paginator('list_tags_of_resource')
        page_iterator = paginator.paginate(ResourceArn=table['TableArn'])
        list_of_tag_lists = map(lambda page: page['Tags'], page_iterator)
        result['Tags'] = flatten_list(list_of_tag_lists)
    except Exception as e:
        print('Error fetching tag info for dynamodb table "{arn}".\nError: {error}'.format(arn=table['TableArn'], error=str(e)))
        result['Tags'] = []

    return result

def get_complete_elbs(client, elbs):
    result = []

    elbNames = []
    elbMap = {}
    for val in elbs:
        elbName = val['LoadBalancerName']
        elbNames.append(elbName)
        elbMap[elbName] = val

    tagInfoForAllElbs = []
    try:
        if len(elbNames) > 0:
            tagInfoForAllElbs = client.describe_tags(LoadBalancerNames=elbNames)['TagDescriptions']
    except Exception as e:
        print('Error fetching tag info for elbs.\nError: {error}'.format(error=str(e)))

    for tagInfo in tagInfoForAllElbs:
        elbName = tagInfo['LoadBalancerName']
        completeElb = elbMap.get(elbName).copy()
        completeElb.update(tagInfo)
        result.append(completeElb)

    return result

def get_complete_rds_resource(client, resource, arnProp):
    arn = resource[arnProp]
    result = resource.copy()
    try:
        tagInfo = client.list_tags_for_resource(ResourceName=arn)
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except Exception as e:
        print('Error fetching tag info for rds resource with ARN: "{arn}".\nError: {error}'.format(arn=arn, error=str(e)))
        result['TagList'] = []
    return result

def get_complete_s3_bucket(client, bucket):
    result = bucket.copy()
    try:
        tagInfo = client.get_bucket_tagging(Bucket=bucket['Name'])
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchTagSet':
            print('Error ({code}) fetching tag info for bucket "{name}".\nError: {error}'.format(code=e.response['Error']['Code'], name=bucket['Name'], error=str(e)))
        result['TagSet'] = []
    return result

def get_complete_sns_topic(client, topic):
    result = topic.copy()
    try:
        tagInfo = client.list_tags_for_resource(ResourceArn=topic['TopicArn'])
        del tagInfo['ResponseMetadata']
        result.update(tagInfo)
    except Exception as e:
        print('Error fetching tag info for topic "{name}".\nError: {error}'.format(name=topic['TopicArn'], error=str(e)))
        result['Tags'] = []
    return result

def get_account_resources(session, target_info, calculateCount):
    cloudfront = session.create_client(
        'cloudfront', region_name=target_info.region)
    ec2 = session.create_client('ec2', region_name=target_info.region)

    cloudfrontDistributions = get_cloudfront_distributions(
        cloudfront, target_info)
    vpnGateways = make_request(
        ec2.describe_vpn_gateways, target_info, 'ec2:describe_vpn_gateways', 'VpnGateways')
    vpcPeeringConnections = make_request(ec2.describe_vpc_peering_connections,
        target_info, 'ec2:describe_vpc_peering_connections', 'VpcPeeringConnections')

    if not COUNT:
        print('Getting additional metadata for account resources')
        cloudfrontDistributions = [get_complete_cloudfront_distribution(cloudfront, distribution) for distribution in cloudfrontDistributions]

    numOfResources = 0
    numOfComputeResources = 0

    if calculateCount:
        numOfResources = len(cloudfrontDistributions)             + len(vpnGateways)             + len(vpcPeeringConnections) 
    return [{
        'cloudFront': {
            'distributions': cloudfrontDistributions,
        },
        'ec2': {
            'vpnGateways': vpnGateways,
            'vpcPeeringConnections': vpcPeeringConnections,
        },
    }, {
        'resources': numOfResources,
        'computeResources': numOfComputeResources,
    }]


def create_json(session, target_info):
    elbv2 = session.create_client('elbv2', region_name=target_info.region)
    autoscaling = session.create_client(
        'autoscaling', region_name=target_info.region)
    dynamodb = session.create_client(
        'dynamodb', region_name=target_info.region)
    ec2 = session.create_client('ec2', region_name=target_info.region)
    elb = session.create_client('elb', region_name=target_info.region)
    lambdaClient = session.create_client(
        'lambda', region_name=target_info.region)
    rds = session.create_client('rds', region_name=target_info.region)
    redshift = session.create_client(
        'redshift', region_name=target_info.region)
    s3 = session.create_client('s3', region_name=target_info.region)
    sns = session.create_client('sns', region_name=target_info.region)
    sqs = session.create_client('sqs', region_name=target_info.region)

    snsTopics = make_request(
        sns.list_topics, target_info, 'sns:list_topics', 'Topics')

    sqsQueueUrls = make_request(
        sqs.list_queues, target_info, 'sqs:list_queues', 'QueueUrls')

    dynamoDbTableNames = make_request(
        dynamodb.list_tables, target_info, 'dynamodb:list_tables', 'TableNames')
    dynamoDbTables = get_dynamoDB_tables(dynamodb, dynamoDbTableNames, target_info)
    vpcs = make_request(ec2.describe_vpcs, target_info,
                        'ec2:describe_vpcs', 'Vpcs')
    subnets = make_request(ec2.describe_subnets, target_info,
                           'ec2:describe_subnets', 'Subnets')
    instances = make_request(
        ec2.describe_instances, target_info, 'ec2:describe_instances', 'Reservations', True)
    volumes = make_request(ec2.describe_volumes, target_info,
                           'ec2:describe_volumes', 'Volumes')
    networkAcls = make_request(
        ec2.describe_network_acls, target_info, 'ec2:describe_network_acls', 'NetworkAcls')
    elbLoadBalancers = make_request(
        elb.describe_load_balancers, target_info, 'elb:describe_load_balancers', 'LoadBalancerDescriptions')
    albLoadBalancers = make_request(
        elbv2.describe_load_balancers, target_info, 'elbv2:describe_load_balancers', 'LoadBalancers')
    targetGroups = make_request(
        elbv2.describe_target_groups, target_info, 'elbv2:describe_target_groups', 'TargetGroups')
    targetHealthDescriptions = get_elb2_target_health(elbv2, targetGroups, target_info)
    autoscalingGroups = make_request(autoscaling.describe_auto_scaling_groups,
                                     target_info, 'autoscaling:describe_auto_scaling_groups', 'AutoScalingGroups')
    allS3Buckets = make_request(s3.list_buckets, target_info,
                             's3:list_buckets', 'Buckets')
    bucketsForRegion = filter_s3_buckets_to_target_region(s3, allS3Buckets, target_info)
    topics = get_sns_topics(sns, snsTopics, target_info)

    queues = get_sqs_queues(sqs, sqsQueueUrls, target_info)
    rdsDbInstances = make_request(
        rds.describe_db_instances, target_info, 'rds.describe_db_instances', 'DBInstances')
    internetGateways = make_request(
        ec2.describe_internet_gateways, target_info, 'ec2:describe_internet_gateways', 'InternetGateways')
    natGateways = make_request(
        ec2.describe_nat_gateways, target_info, 'ec2:describe_nat_gateways', 'NatGateways')
    transitGateways = make_request(
        ec2.describe_transit_gateways, target_info, 'ec2:describe_transit_gateways', 'TransitGateways')
    routeTables = make_request(
        ec2.describe_route_tables, target_info, 'ec2:describe_route_tables', 'RouteTables')
    vpcEndpoints = make_request(
        ec2.describe_vpc_endpoints, target_info, 'ec2:describe_vpc_endpoints', 'VpcEndpoints')
    lambdaFunctions = get_lambda_functions(lambdaClient, target_info)
    rdsDbClusters = make_request(
        rds.describe_db_clusters, target_info, 'rds.describe_db_clusters', 'DBClusters')
    redshiftClusters = make_request(
        redshift.describe_clusters, target_info, 'rds.describe_clusters', 'Clusters')

    if not COUNT:
        print('Getting additional metadata for region resources')
        albLoadBalancers, targetGroups = get_complete_albs(elbv2, albLoadBalancers, targetGroups)
        dynamoDbTables = [get_complete_dynamodb_table(dynamodb, table) for table in dynamoDbTables]
        elbLoadBalancers = get_complete_elbs(elb, elbLoadBalancers)
        rdsDbInstances = [get_complete_rds_resource(rds, instance, 'DBInstanceArn') for instance in rdsDbInstances]
        rdsDbClusters = [get_complete_rds_resource(rds, cluster, 'DBClusterArn') for cluster in rdsDbClusters]
        bucketsForRegion = [get_complete_s3_bucket(s3, bucket) for bucket in bucketsForRegion]
        topics = [get_complete_sns_topic(sns, topic) for topic in topics]

    count_data = {
        'computeResources': len(instances) + len(lambdaFunctions),
        'resources': len(vpcs)             + len(subnets)             + len(instances)             + len(volumes)             + len(networkAcls)             + len(elbLoadBalancers)             + len(albLoadBalancers)             + len(autoscalingGroups)             + len(bucketsForRegion)             + len(queues)             + len(topics)             + len(rdsDbInstances)             + len(internetGateways)             + len(natGateways)             + len(transitGateways)             + len(routeTables)             + len(vpcEndpoints)             + len(lambdaFunctions)             + len(rdsDbClusters)             + len(dynamoDbTables)             + len(redshiftClusters)
    }
    infrastructure_data = {
        'alb': {
            'loadBalancersV2': albLoadBalancers,
            'targetGroups': targetGroups,
            'targetHealthDescription': targetHealthDescriptions,

        },
        'autoscaling': {
            'groups': autoscalingGroups,
            'launchConfiguration': make_request(autoscaling.describe_launch_configurations, target_info, 'autoscaling:describe_launch_configurations', 'LaunchConfigurations'),
        },
        'dynamoDB': {
            'tables': dynamoDbTables,
        },
        'ec2': {
            'instances': instances,
            'networkAcls': networkAcls,
            'securityGroups': make_request(ec2.describe_security_groups, target_info, 'ec2:describe_security_groups', 'SecurityGroups'),
            'subnets': subnets,
            'volumes': volumes,
            'vpcs': vpcs,
            'internetGateways': internetGateways,
            'natGateways': natGateways,
            'transitGateways': transitGateways,
            'routeTables': routeTables,
            'vpcEndpoints': vpcEndpoints,
        },
        'elb': {
            'loadBalancers': elbLoadBalancers,
        },
        'iam': {
            'attachedPolicies': [],
            'roles': [],
            'rolePolicies': [],
        },
        'lambda': {
            'functions': lambdaFunctions,
        },
        'rds': {
            'dbInstances': rdsDbInstances,
            'dbClusters': rdsDbClusters,
        },
        'redshift': {
            'clusters': redshiftClusters,
        },
        's3': {
            'buckets': bucketsForRegion,
        },
        'sns': {
            'topics': topics,
        },
        'sqs': {
            'queues': queues,
        },
    }

    return [
        infrastructure_data,
        count_data
    ]


def get_account(target_info, session):
    try:
        sts = session.create_client('sts', region_name=target_info.region)
        account = make_request(sts.get_caller_identity, target_info,
                               'sts:get_caller_identity', 'Account')
        return account
    except Exception as e:
        handle_error(target_info, e, 'Could not create session:')
        return None


def process_args():
    parser = ArgumentParser()
    parser.add_argument('-r', '--regions', help=usage,
                        nargs='+', type=str, action='append')
    parser.add_argument('-p', '--profile', help=usage,
                        type=str, action='append')
    parser.add_argument(
        '-c', '--count', help="count number of AWS resources", action='store_true')
    return parser.parse_args()


def generateTargets(args):
    profiles = args.profile
    regions = args.regions
    if not profiles or not regions:
        return []

    if len(profiles) != len(regions):
        return []

    profileRegions = list(zip(profiles, regions))
    targets = []
    for profileRegion in profileRegions:
        for region in profileRegion[1]:
            targets.append(AwsImportTarget(profileRegion[0], region))

    return targets

def print_errors():
    print("\nErrors occurred while importing:")
    for error in ERRORS:
        print(error)

def print_to_file(contents, file_name, message):
    with open(file_name, 'w') as f:
        json.dump(contents, f, indent=4, cls=DateTimeEncoder)
        print(message)

def import_aws():
    args = process_args()
    global COUNT
    COUNT = args.count
    targets = generateTargets(args)

    if not targets:
        print(usage)
        return

    accounts = {}
    total_resource_count = 0
    total_compute_resource_count = 0

    for target in targets:
        session = botocore.session.Session(profile=target.profile_name)
        account = get_account(target, session)
        account_hash = encrypt_string(account)

        if not account:
            handle_error(
                target, 'Could not get account info (double check your profile name / region)', 'Unable to import account:')
            continue

        region_resources = create_json(session, target)

        if COUNT:
            if account_hash not in accounts:
                account_resources = get_account_resources(session, target, args.count)
                total_resource_count += account_resources[1]['resources']
                accounts[account_hash] = {
                    'resourceCount': account_resources[1]['resources'],
                    'computeResourceCount': 0
                }
            accounts[account_hash]['resourceCount'] = accounts[account_hash]['resourceCount'] + region_resources[1]['resources']
            accounts[account_hash]['computeResourceCount'] = accounts[account_hash]['computeResourceCount'] + region_resources[1]['computeResources']
            total_resource_count += region_resources[1]['resources']
            total_compute_resource_count += region_resources[1]['computeResources']
        else:
            if account_hash not in accounts:
                account_resources = get_account_resources(session, target, args.count)
                accounts[account_hash] = {
                    'accountId': account,
                    'resources': account_resources[0],
                    'regions': []
                }
            accounts[account_hash]['regions'].append({
                'regionId': target.region,
                'resources': region_resources[0]
            })

    if COUNT:
        results = {
            'totalResourceCount': total_resource_count,
            'totalComputeResourceCount': total_compute_resource_count,
            'accounts': accounts
        }
        if ERRORS:
            print_errors()
        if accounts.values():
            print_to_file(results, 'count.json', '\nResource count output to count.json')
    else:
        results = {
            'accounts': list(accounts.values())
        }
        if ERRORS:
            print_errors()
            if accounts.values():
                print("\nYou can import this file, however resources and accounts that experienced errors will not appear")
        if accounts.values():
            print_to_file(results, 'aws.json', '\nAWS Resources output to aws.json')


def getBotocoreVersionWarning(pipCommandName):
    return 'WARNING: You are using version ' + botocore.__version__ + ' of the botocore python module.\nThe import in Lucidchart may fail if you are not using version ' + requiredBotocoreVersion + '.\nChange the version by running "' + pipCommandName + ' install --force-reinstall botocore==' + requiredBotocoreVersion + '".\nPress Enter to quit or type "continue" to continue with the script: '

if botocore.__version__ != requiredBotocoreVersion:
    if sys.version_info > (3,0):
        response = input(getBotocoreVersionWarning('pip3'))
    else:
        response = raw_input(getBotocoreVersionWarning('pip'))

    if response != 'continue':
        exit()

import_aws()
