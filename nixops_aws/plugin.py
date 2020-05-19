
from typing import Union, Optional, Dict, List, TypeVar, Generic
from typing_extensions import Literal

T = TypeVar("T")
class NixOpsRef(Generic[T]):
    pass
class NixOpsUnknown(Generic[T]):
    pass



import os.path
import nixops.plugins
from nixops.plugins import NixOpsPlugin, hookimpl, MachineBackendRegistration, ResourceBackendRegistration
from typing import List
from pathlib import Path



import nixops_aws.backends.ec2
import nixops_aws.resources.aws_vpn_connection
import nixops_aws.resources.aws_vpn_connection_route
import nixops_aws.resources.aws_vpn_gateway
import nixops_aws.resources.cloudwatch_log_group
import nixops_aws.resources.cloudwatch_log_stream
import nixops_aws.resources.cloudwatch_metric_alarm
import nixops_aws.resources.ebs_volume
import nixops_aws.resources.ec2_keypair
import nixops_aws.resources.ec2_placement_group
import nixops_aws.resources.ec2_rds_dbinstance
import nixops_aws.resources.ec2_rds_dbsecurity_group
import nixops_aws.resources.ec2_security_group
import nixops_aws.resources.elastic_file_system
import nixops_aws.resources.elastic_file_system_mount_target
import nixops_aws.resources.elastic_ip
import nixops_aws.resources.iam_role
import nixops_aws.resources.route53_health_check
import nixops_aws.resources.route53_hosted_zone
import nixops_aws.resources.route53_recordset
import nixops_aws.resources.s3_bucket
import nixops_aws.resources.sns_topic
import nixops_aws.resources.sqs_queue
import nixops_aws.resources.vpc
import nixops_aws.resources.vpc_customer_gateway
import nixops_aws.resources.vpc_dhcp_options
import nixops_aws.resources.vpc_egress_only_internet_gateway
import nixops_aws.resources.vpc_endpoint
import nixops_aws.resources.vpc_internet_gateway
import nixops_aws.resources.vpc_nat_gateway
import nixops_aws.resources.vpc_network_acl
import nixops_aws.resources.vpc_network_interface
import nixops_aws.resources.vpc_network_interface_attachment
import nixops_aws.resources.vpc_route
import nixops_aws.resources.vpc_route_table
import nixops_aws.resources.vpc_route_table_association
import nixops_aws.resources.vpc_subnet

class NixOpsAWSPlugin(NixOpsPlugin):
    def machine_backends(self) -> List[MachineBackendRegistration]:
        return [

            MachineBackendRegistration(
                database_name="ec2",
                nix_name="ec2",
                definition_record=nixops_aws.backends.ec2.EC2Definition,
                state_record=nixops_aws.backends.ec2.EC2State,
            ),

        ]


    def resource_backends(self) -> List[ResourceBackendRegistration]:
        return [

            ResourceBackendRegistration(
                database_name="aws-vpn-connection",
                nix_name="awsVPNConnections",
                definition_record=nixops_aws.resources.aws_vpn_connection.AWSVPNConnectionDefinition,
                state_record=nixops_aws.resources.aws_vpn_connection.AWSVPNConnectionState,
            ),
            ResourceBackendRegistration(
                database_name="aws-vpn-connection-route",
                nix_name="awsVPNConnectionRoutes",
                definition_record=nixops_aws.resources.aws_vpn_connection_route.AWSVPNConnectionRouteDefinition,
                state_record=nixops_aws.resources.aws_vpn_connection_route.AWSVPNConnectionRouteState,
            ),
            ResourceBackendRegistration(
                database_name="aws-vpn-gateway",
                nix_name="awsVPNGateways",
                definition_record=nixops_aws.resources.aws_vpn_gateway.AWSVPNGatewayDefinition,
                state_record=nixops_aws.resources.aws_vpn_gateway.AWSVPNGatewayState,
            ),
            ResourceBackendRegistration(
                database_name="cloudwatch-log-group",
                nix_name="cloudwatchLogGroups",
                definition_record=nixops_aws.resources.cloudwatch_log_group.CloudWatchLogGroupDefinition,
                state_record=nixops_aws.resources.cloudwatch_log_group.CloudWatchLogGroupState,
            ),
            ResourceBackendRegistration(
                database_name="cloudwatch-log-stream",
                nix_name="cloudwatchLogStreams",
                definition_record=nixops_aws.resources.cloudwatch_log_stream.CloudWatchLogStreamDefinition,
                state_record=nixops_aws.resources.cloudwatch_log_stream.CloudWatchLogStreamState,
            ),
            ResourceBackendRegistration(
                database_name="cloudwatch-metric-alarm",
                nix_name="cloudwatchMetricAlarms",
                definition_record=nixops_aws.resources.cloudwatch_metric_alarm.CloudwatchMetricAlarmDefinition,
                state_record=nixops_aws.resources.cloudwatch_metric_alarm.CloudwatchMetricAlarmState,
            ),
            ResourceBackendRegistration(
                database_name="ebs-volume",
                nix_name="ebsVolumes",
                definition_record=nixops_aws.resources.ebs_volume.EBSVolumeDefinition,
                state_record=nixops_aws.resources.ebs_volume.EBSVolumeState,
            ),
            ResourceBackendRegistration(
                database_name="ec2-keypair",
                nix_name="ec2KeyPairs",
                definition_record=nixops_aws.resources.ec2_keypair.EC2KeyPairDefinition,
                state_record=nixops_aws.resources.ec2_keypair.EC2KeyPairState,
            ),
            ResourceBackendRegistration(
                database_name="ec2-placement-group",
                nix_name="ec2PlacementGroups",
                definition_record=nixops_aws.resources.ec2_placement_group.EC2PlacementGroupDefinition,
                state_record=nixops_aws.resources.ec2_placement_group.EC2PlacementGroupState,
            ),
            ResourceBackendRegistration(
                database_name="ec2-rds-dbsecurity-group",
                nix_name="rdsDbSecurityGroups",
                definition_record=nixops_aws.resources.ec2_rds_dbsecurity_group.EC2RDSDbSecurityGroupDefinition,
                state_record=nixops_aws.resources.ec2_rds_dbsecurity_group.EC2RDSDbSecurityGroupState,
            ),
            ResourceBackendRegistration(
                database_name="ec2-rds-dbinstance",
                nix_name="rdsDbInstances",
                definition_record=nixops_aws.resources.ec2_rds_dbinstance.EC2RDSDbInstanceDefinition,
                state_record=nixops_aws.resources.ec2_rds_dbinstance.EC2RDSDbInstanceState,
            ),
            ResourceBackendRegistration(
                database_name="vpc",
                nix_name="vpc",
                definition_record=nixops_aws.resources.vpc.VPCDefinition,
                state_record=nixops_aws.resources.vpc.VPCState,
            ),
            ResourceBackendRegistration(
                database_name="elastic-ip",
                nix_name="elasticIPs",
                definition_record=nixops_aws.resources.elastic_ip.ElasticIPDefinition,
                state_record=nixops_aws.resources.elastic_ip.ElasticIPState,
            ),
            ResourceBackendRegistration(
                database_name="ec2-security-group",
                nix_name="ec2SecurityGroups",
                definition_record=nixops_aws.resources.ec2_security_group.EC2SecurityGroupDefinition,
                state_record=nixops_aws.resources.ec2_security_group.EC2SecurityGroupState,
            ),
            ResourceBackendRegistration(
                database_name="elastic-file-system",
                nix_name="elasticFileSystems",
                definition_record=nixops_aws.resources.elastic_file_system.ElasticFileSystemDefinition,
                state_record=nixops_aws.resources.elastic_file_system.ElasticFileSystemState,
            ),
            ResourceBackendRegistration(
                database_name="elastic-file-system-mount-target",
                nix_name="elasticFileSystemMountTargets",
                definition_record=nixops_aws.resources.elastic_file_system_mount_target.ElasticFileSystemMountTargetDefinition,
                state_record=nixops_aws.resources.elastic_file_system_mount_target.ElasticFileSystemMountTargetState,
            ),
            ResourceBackendRegistration(
                database_name="iam-role",
                nix_name="iamRoles",
                definition_record=nixops_aws.resources.iam_role.IAMRoleDefinition,
                state_record=nixops_aws.resources.iam_role.IAMRoleState,
            ),
            ResourceBackendRegistration(
                database_name="aws-route53-health-check",
                nix_name="route53HealthChecks",
                definition_record=nixops_aws.resources.route53_health_check.Route53HealthCheckDefinition,
                state_record=nixops_aws.resources.route53_health_check.Route53HealthCheckState,
            ),
            ResourceBackendRegistration(
                database_name="aws-route53-hosted-zone",
                nix_name="route53HostedZones",
                definition_record=nixops_aws.resources.route53_hosted_zone.Route53HostedZoneDefinition,
                state_record=nixops_aws.resources.route53_hosted_zone.Route53HostedZoneState,
            ),
            ResourceBackendRegistration(
                database_name="aws-route53-recordset",
                nix_name="route53RecordSets",
                definition_record=nixops_aws.resources.route53_recordset.Route53RecordSetDefinition,
                state_record=nixops_aws.resources.route53_recordset.Route53RecordSetState,
            ),
            ResourceBackendRegistration(
                database_name="s3-bucket",
                nix_name="s3Buckets",
                definition_record=nixops_aws.resources.s3_bucket.S3BucketDefinition,
                state_record=nixops_aws.resources.s3_bucket.S3BucketState,
            ),
            ResourceBackendRegistration(
                database_name="sns-topic",
                nix_name="snsTopics",
                definition_record=nixops_aws.resources.sns_topic.SNSTopicDefinition,
                state_record=nixops_aws.resources.sns_topic.SNSTopicState,
            ),
            ResourceBackendRegistration(
                database_name="sqs-queue",
                nix_name="sqsQueues",
                definition_record=nixops_aws.resources.sqs_queue.SQSQueueDefinition,
                state_record=nixops_aws.resources.sqs_queue.SQSQueueState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-customer-gateway",
                nix_name="vpcCustomerGateways",
                definition_record=nixops_aws.resources.vpc_customer_gateway.VPCCustomerGatewayDefinition,
                state_record=nixops_aws.resources.vpc_customer_gateway.VPCCustomerGatewayState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-dhcp-options",
                nix_name="vpcDhcpOptions",
                definition_record=nixops_aws.resources.vpc_dhcp_options.VPCDhcpOptionsDefinition,
                state_record=nixops_aws.resources.vpc_dhcp_options.VPCDhcpOptionsState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-egress-only-internet-gateway",
                nix_name="vpcEgressOnlyInternetGateways",
                definition_record=nixops_aws.resources.vpc_egress_only_internet_gateway.VPCEgressOnlyInternetGatewayDefinition,
                state_record=nixops_aws.resources.vpc_egress_only_internet_gateway.VPCEgressOnlyInternetGatewayState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-subnet",
                nix_name="vpcSubnets",
                definition_record=nixops_aws.resources.vpc_subnet.VPCSubnetDefinition,
                state_record=nixops_aws.resources.vpc_subnet.VPCSubnetState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-route-table",
                nix_name="vpcRouteTables",
                definition_record=nixops_aws.resources.vpc_route_table.VPCRouteTableDefinition,
                state_record=nixops_aws.resources.vpc_route_table.VPCRouteTableState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-endpoint",
                nix_name="vpcEndpoints",
                definition_record=nixops_aws.resources.vpc_endpoint.VPCEndpointDefinition,
                state_record=nixops_aws.resources.vpc_endpoint.VPCEndpointState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-internet-gateway",
                nix_name="vpcInternetGateways",
                definition_record=nixops_aws.resources.vpc_internet_gateway.VPCInternetGatewayDefinition,
                state_record=nixops_aws.resources.vpc_internet_gateway.VPCInternetGatewayState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-nat-gateway",
                nix_name="vpcNatGateways",
                definition_record=nixops_aws.resources.vpc_nat_gateway.VPCNatGatewayDefinition,
                state_record=nixops_aws.resources.vpc_nat_gateway.VPCNatGatewayState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-network-acl",
                nix_name="vpcNetworkAcls",
                definition_record=nixops_aws.resources.vpc_network_acl.VPCNetworkAclDefinition,
                state_record=nixops_aws.resources.vpc_network_acl.VPCNetworkAclState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-network-interface",
                nix_name="vpcNetworkInterfaces",
                definition_record=nixops_aws.resources.vpc_network_interface.VPCNetworkInterfaceDefinition,
                state_record=nixops_aws.resources.vpc_network_interface.VPCNetworkInterfaceState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-network-interface-attachment",
                nix_name="vpcNetworkInterfaceAttachments",
                definition_record=nixops_aws.resources.vpc_network_interface_attachment.VPCNetworkInterfaceAttachmentDefinition,
                state_record=nixops_aws.resources.vpc_network_interface_attachment.VPCNetworkInterfaceAttachmentState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-route",
                nix_name="vpcRoutes",
                definition_record=nixops_aws.resources.vpc_route.VPCRouteDefinition,
                state_record=nixops_aws.resources.vpc_route.VPCRouteState,
            ),
            ResourceBackendRegistration(
                database_name="vpc-route-table-association",
                nix_name="vpcRouteTableAssociations",
                definition_record=nixops_aws.resources.vpc_route_table_association.VPCRouteTableAssociationDefinition,
                state_record=nixops_aws.resources.vpc_route_table_association.VPCRouteTableAssociationState,
            ),

        ]


    def nix_expression_files(self) -> List[Path]:
        return [Path(__file__).resolve().parent / "nix"]


@hookimpl
def register_plugin() -> NixOpsPlugin:
    return NixOpsAWSPlugin()


class VPCEgressOnlyInternetGatewayOptions(nixops.resources.ResourceOptions):
    # Name of the VPC egress only internet gateway.
    name: str
    # The ID of the VPC where the internet gateway will be created
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
class ElasticFileSystemMountTargetOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # The Elastic File System to which this mount target refers.
    fileSystem: Union[str, NixOpsUnknown[Literal['resource of type ‘elastic-file-system’']]]
    # The IP address of the mount target in the subnet. If unspecified, EC2 will automatically assign an address.
    ipAddress: Optional[str]
    # AWS region.
    region: str
    # The EC2 security groups associated with the mount target's network interface.
    securityGroups: List[str]
    # The EC2 subnet in which to create this mount target.
    subnet: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
class Route53HostedZoneOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.  If left empty, it defaults to the
    # contents of the environment variables
    # <envar>EC2_ACCESS_KEY</envar> or
    # <envar>AWS_ACCESS_KEY_ID</envar> (in that order).  The
    # corresponding Secret Access Key is not specified in the
    # deployment model, but looked up in the file
    # <filename>~/.ec2-keys</filename>, which should specify, on
    # each line, an Access Key ID followed by the corresponding
    # Secret Access Key. If the lookup was unsuccessful it is continued
    # in the standard AWS tools <filename>~/.aws/credentials</filename> file.
    # If it does not appear in these files, the
    # environment variables
    # <envar>EC2_SECRET_KEY</envar> or
    # <envar>AWS_SECRET_ACCESS_KEY</envar> are used.
    accessKeyId: str
    # VPCs
    associatedVPCs: List[NixOpsUnknown[Literal['submodule']]]
    # Comments that you want to include about the hosted zone.
    comment: str
    # List of nameserves in the delegation set after creation. Set by nixops.
    delegationSet: List[str]
    # Name of the recordset.
    name: str
    # Whether this is a private hosted zone.
    privateZone: bool
class VPCNetworkAclOptions(nixops.resources.ResourceOptions):
    # The network ACL entries
    entries: List[NixOpsUnknown[Literal['submodule']]]
    # Name of the DHCP options set.
    name: str
    # The network ACL id generated from AWS. This is set by NixOps
    networkAclId: str
    # A list of subnet IDs to apply to the ACL to.
    subnetIds: List[Union[str, NixOpsRef[Literal['vpc-subnet']]]]
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The Id of the associated VPC.
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
class EBSVolumeOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # AWS region.
    region: str
    # The snapshot ID from which this volume will be created.  If
    # not specified, an empty volume is created.  Changing the
    # snapshot ID has no effect if the volume already exists.
    snapshot: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The volume id to be imported into the NixOps ebs-volume resource.
    volumeId: str
    # The EC2 availability zone in which the volume should be
    # created.
    zone: str
class CloudwatchMetricAlarmOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.  If left empty, it defaults to the
    # contents of the environment variables
    # <envar>EC2_ACCESS_KEY</envar> or
    # <envar>AWS_ACCESS_KEY_ID</envar> (in that order).  The
    # corresponding Secret Access Key is not specified in the
    # deployment model, but looked up in the file
    # <filename>~/.ec2-keys</filename>, which should specify, on
    # each line, an Access Key ID followed by the corresponding
    # Secret Access Key. If the lookup was unsuccessful it is continued
    # in the standard AWS tools <filename>~/.aws/credentials</filename> file.
    # If it does not appear in these files, the
    # environment variables
    # <envar>EC2_SECRET_KEY</envar> or
    # <envar>AWS_SECRET_ACCESS_KEY</envar> are used.
    accessKeyId: str
    # The actions to execute when this alarm transitions to the ALARM state from
    # any other state.
    alarmActions: List[Union[str, NixOpsUnknown[Literal['resource of type ‘sns-topic’']]]]
    # The arithmetic operation to use when comparing the specified statistic and
    # threshold. The specified statistic value is used as the first operand.
    comparisonOperator: Union[Literal["GreaterThanOrEqualToThreshold"], Literal["GreaterThanThreshold"], Literal["LessThanThreshold"], Literal["LessThanOrEqualToThreshold"]]
    # The number of datapoints that must be breaching to trigger the alarm.
    datapointsToAlarm: int
    # The dimensions for the metric associated with the alarm.
    dimensions: List[NixOpsUnknown[Literal['submodule']]]
    # The number of periods over which data is compared to the specified threshold.
    evaluationPeriods: int
    # The actions to execute when this alarm transitions to the INSUFFICIENT_DATA
    # state from any other state.
    insufficientDataActions: List[Union[str, NixOpsUnknown[Literal['resource of type ‘sns-topic’']]]]
    # The name of the metric associated with the alarm.
    metricName: str
    # Name of the CloudWatch Metric Alarm.
    name: str
    # The namespace of the metric associated with the alarm.
    namespace: str
    # The actions to execute when this alarm transitions to the OK state from
    # any other state.
    okActions: List[Union[str, NixOpsUnknown[Literal['resource of type ‘sns-topic’']]]]
    # The period, in seconds, over which the statistic is applied.
    period: int
    # AWS region.
    region: str
    # The statistic for the metric associated with the alarm, other than percentile.
    statistic: Union[Literal["SampleCount"], Literal["Average"], Literal["Sum"], Literal["Minimum"], Literal["Maximum"]]
    # The value to compare with the specified statistic.
    threshold: int
    # How this alarm is to handle missing data points.
    treatMissingData: Union[Literal["breaching"], Literal["notBreaching"], Literal["ignore"], Literal["missing"]]
    # The unit of the metric associated with the alarm.
    unit: Union[Literal["Seconds"], Literal["Microseconds"], Literal["Milliseconds"], Literal["Bytes"], Literal["Kilobytes"], Literal["Megabytes"], Literal["Gigabytes"], Literal["Terabytes"], Literal["Bits"], Literal["Kilobits"], Literal["Megabits"], Literal["Gigabits"], Literal["Terabits"], Literal["Percent"], Literal["Count"], Literal["Bytes/Second"], Literal["Kilobytes/Second"], Literal["Megabytes/Second"], Literal["Gigabytes/Second"], Literal["Terabytes/Second"], Literal["Bits/Second"], Literal["Kilobits/Second"], Literal["Megabits/Second"], Literal["Gigabits/Second"], Literal["Terabits/Second"], Literal["Count/Second"], Literal["None"]]
class VPCRouteTableAssociationOptions(nixops.resources.ResourceOptions):
    # Name of the VPC route table association.
    name: str
    # The ID of the VPC route table
    routeTableId: Union[str, NixOpsRef[Literal['vpc-route-table']]]
    # The ID of the VPC subnet where the route table will be associated
    subnetId: Union[str, NixOpsRef[Literal['vpc-subnet']]]
class VPCInternetGatewayOptions(nixops.resources.ResourceOptions):
    # Name of the VPC internet gateway.
    name: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The ID of the VPC where the internet gateway will be created
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
class VPCOptions(nixops.resources.ResourceOptions):
    # Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for the VPC.
    # You cannot specify the range of IP addresses, or the size of the CIDR block.
    amazonProvidedIpv6CidrBlock: bool
    # The CIDR block for the VPC
    cidrBlock: str
    # Enables a VPC for ClassicLink. You can then link EC2-Classic instances to your
    # ClassicLink-enabled VPC to allow communication over private IP addresses.
    # You cannot enable your VPC for ClassicLink if any of your VPC’s route tables
    # have existing routes for address ranges within the 10.0.0.0/8 IP address range
    # , excluding local routes for VPCs in the 10.0.0.0/16 and 10.1.0.0/16 IP address ranges.
    enableClassicLink: bool
    # Specifies whether DNS hostnames are provided for the instances launched in this VPC.
    # You can only set this attribute to true if EnableDnsSupport is also true.
    enableDnsHostnames: bool
    # Specifies whether the DNS server provided by Amazon is enabled for the VPC.
    enableDnsSupport: bool
    # The supported tenancy options for instances launched
    # into the VPC. Valid values are "default" and "dedicated".
    instanceTenancy: str
    # Name of the VPC.
    name: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The VPC id generated from AWS. This is set by NixOps
    vpcId: str
class Route53RecordSetOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.  If left empty, it defaults to the
    # contents of the environment variables
    # <envar>EC2_ACCESS_KEY</envar> or
    # <envar>AWS_ACCESS_KEY_ID</envar> (in that order).  The
    # corresponding Secret Access Key is not specified in the
    # deployment model, but looked up in the file
    # <filename>~/.ec2-keys</filename>, which should specify, on
    # each line, an Access Key ID followed by the corresponding
    # Secret Access Key. If the lookup was unsuccessful it is continued
    # in the standard AWS tools <filename>~/.aws/credentials</filename> file.
    # If it does not appear in these files, the
    # environment variables
    # <envar>EC2_SECRET_KEY</envar> or
    # <envar>AWS_SECRET_ACCESS_KEY</envar> are used.
    accessKeyId: str
    # The DNS name to bind.
    domainName: str
    # Optional ID of an Amazon Route 53 health check.
    healthCheckId: Union[str, NixOpsUnknown[Literal['resource of type ‘route53-health-check’']]]
    # Name of the recordset.
    name: str
    # DNS record type
    recordType: Union[Literal["A"], Literal["AAAA"], Literal["TXT"], Literal["CNAME"], Literal["MX"], Literal["NAPT"], Literal["PTR"], Literal["SRV"], Literal["SPF"]]
    # The value of the DNS record
    # (e.g. IP address in case of an A or AAA record type,
    #  or a DNS name in case of a CNAME record type)
    recordValues: List[Union[str, NixOpsUnknown[Literal['resource of type ‘machine’']]]]
    # DNS record type
    routingPolicy: Union[Literal["simple"], Literal["weighted"], Literal["multivalue"]]
    # A unique identifier that differentiates among multiple
    # resource record sets that have the same combination of
    # DNS name and type.
    setIdentifier: str
    # The time to live (TTL) for the A record created for the
    # specified DNS hostname.
    ttl: int
    # Among resource record sets that have the same combination
    # of DNS name and type, a value that determines what portion
    # of traffic for the current resource record set is routed
    # to the associated location. When value is 0, weighted
    # routing policy is not used.
    weight: int
    # The DNS hosted zone id. If null, the zoneName will be used to look up the zoneID
    zoneId: Optional[Union[str, NixOpsUnknown[Literal['resource of type ‘route53-hosted-zone’']]]]
    # The DNS name of the hosted zone
    zoneName: Optional[str]
class CloudWatchLogGroupOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Amazon Resource Name (ARN) of the cloudwatch log group. This is set by NixOps.
    arn: str
    # Name of the cloudwatch log group.
    name: str
    # AWS region.
    region: str
    # How long to store log data in a log group
    retentionInDays: Optional[int]
class VPCRouteTableOptions(nixops.resources.ResourceOptions):
    # Name of the VPC route table.
    name: str
    # A list of VPN gateways for propagation.
    propagatingVgws: List[Union[str, NixOpsRef[Literal['aws-vpn-gateway']]]]
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The ID of the VPC where the route table will be created
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
class IAMRoleOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # The IAM AssumeRole policy definition (in JSON format). Empty string (default) uses the existing Assume Role Policy.
    assumeRolePolicy: str
    # Name of the IAM role.
    name: str
    # The IAM policy definition (in JSON format).
    policy: str
class VPCRouteOptions(nixops.resources.ResourceOptions):
    # The IPv4 CIDR address block used for the destination match.
    destinationCidrBlock: Optional[str]
    # The IPv6 CIDR block used for the destination match.
    destinationIpv6CidrBlock: Optional[str]
    # [IPv6 traffic only] The ID of an egress-only Internet gateway.
    egressOnlyInternetGatewayId: Optional[Union[str, NixOpsRef[Literal['vpc-egress-only-internet-gateway']]]]
    # The ID of an Internet gateway or virtual private gateway attached to your VPC.
    gatewayId: Optional[Union[str, NixOpsRef[Literal['vpc-internet-gateway']]]]
    # The ID of a NAT instance in your VPC. The operation fails if you specify an
    # instance ID unless exactly one network interface is attached.
    instanceId: Optional[Union[str, NixOpsUnknown[Literal['EC2 machine']]]]
    # Name of the VPC route.
    name: str
    # The ID of a NAT gateway.
    natGatewayId: Optional[Union[str, NixOpsRef[Literal['vpc-nat-gateway']]]]
    # The ID of a network interface.
    networkInterfaceId: Optional[Union[str, NixOpsRef[Literal['vpc-network-interface']]]]
    # The ID of the VPC route table
    routeTableId: Union[str, NixOpsRef[Literal['vpc-route-table']]]
class EC2PlacementGroupOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Name of the placement group.
    name: str
    # AWS region.
    region: str
    # The placement strategy of the new placement group. Currently, the only acceptable value is “cluster”.
    strategy: str
class CloudWatchLogStreamOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Amazon Resource Name (ARN) of the cloudwatch log stream. This is set by NixOps.
    arn: str
    # The name of the log group under which the log stream is to be created.
    logGroupName: str
    # Name of the cloudwatch log stream.
    name: str
    # AWS region.
    region: str
class ElasticFileSystemOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # AWS region.
    region: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
class EC2SecurityGroupOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Informational description of the security group.
    description: str
    # The security group ID. This is set by NixOps.
    groupId: NixOpsUnknown[Literal['uniq']]
    # Name of the security group.
    name: str
    # AWS region.
    region: str
    # The security group's rules.
    rules: List[NixOpsUnknown[Literal['submodule']]]
    # The VPC ID to create security group in (default is not set, uses default VPC in EC2-VPC account, in EC2-Classic accounts no VPC is set).
    vpcId: NixOpsUnknown[Literal['uniq']]
class EC2KeyPairOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Name of the EC2 key pair.
    name: str
    # AWS region.
    region: str
class VPCNetworkInterfaceAttachmentOptions(nixops.resources.ResourceOptions):
    # The index of the device for the network interface attachment.
    deviceIndex: int
    # ID of the instance to attach to.
    instanceId: Union[str, NixOpsUnknown[Literal['EC2 machine']]]
    # Name of the VPC network interface attachment.
    name: str
    # ENI ID to attach to.
    networkInterfaceId: Union[str, NixOpsRef[Literal['vpc-network-interface']]]

class EC2RDSDbInstanceOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Allocated storage in GB
    allocatedStorage: int
    # Optional database name to be created when instance is first created.
    dbName: str
    # The endpoint address of the database instance.  This is set by NixOps.
    endpoint: str
    # Database engine. See <link
    #       xlink:href='http://boto.readthedocs.org/en/latest/ref/rds.html#boto.rds.RDSConnection.create_dbinstance'
    #       for valid engines.
    engine: str
    # Identifier for RDS database instance
    id: str
    # RDS instance class. See <link
    # xlink:href='http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.html' />
    # for more information.
    instanceClass: str
    # Password for master user.
    masterPassword: str
    # Master username for authentication to database instance.
    masterUsername: str
    # If True, specifies the DB Instance will be deployed in multiple availability zones.
    multiAZ: bool
    # Port for database instance connections.
    port: int
    # Amazon RDS region.
    region: str
    # List of names of DBSecurityGroup to authorize on this DBInstance.
    securityGroups: List[Union[str, NixOpsUnknown[Literal['resource of type ‘ec2-rds-security-group’']]]]
class VPCEndpointOptions(nixops.resources.ResourceOptions):
    # Name of the VPC endpoint.
    name: str
    # A policy to attach to the endpoint that controls access to the service.
    policy: Optional[str]
    # One or more route table IDs.
    routeTableIds: List[Union[str, NixOpsRef[Literal['vpc-route-table']]]]
    # The AWS service name, in the form com.amazonaws.region.service.
    serviceName: str
    # The ID of the VPC where the endpoint will be created.
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
class VPCNetworkInterfaceOptions(nixops.resources.ResourceOptions):
    # A description for the network interface.
    description: str
    # Name of the VPC network interface.
    name: str
    # The primary private IPv4 address of the network interface. If you don't
    # specify an IPv4 address, Amazon EC2 selects one for you from the subnet's
    # IPv4 CIDR range.
    primaryPrivateIpAddress: Optional[str]
    # One or more secondary private IPv4 addresses.
    privateIpAddresses: List[str]
    # The number of secondary private IPv4 addresses to assign to a network interface.
    # When you specify a number of secondary IPv4 addresses, Amazon EC2 selects these
    # IP addresses within the subnet's IPv4 CIDR range.
    # You can't specify this option and specify privateIpAddresses in the same time.
    secondaryPrivateIpAddressCount: Optional[int]
    # The IDs of one or more security groups.
    securityGroups: List[Union[str, NixOpsRef[Literal['ec2-security-group']]]]
    # Indicates whether source/destination checking is enabled.
    # Default value is true.
    sourceDestCheck: bool
    # Subnet Id to create the ENI in.
    subnetId: Union[str, NixOpsRef[Literal['vpc-subnet']]]
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
class SQSQueueOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Amazon Resource Name (ARN) of the queue. This is set by NixOps.
    arn: str
    # Name of the SQS queue.
    name: str
    # AWS region.
    region: str
    # URL of the queue. This is set by NixOps.
    url: str
    # The time interval in seconds after a message has been
    # received until it becomes visible again.
    visibilityTimeout: int
class VPCCustomerGatewayOptions(nixops.resources.ResourceOptions):
    # For devices that support BGP, the customer gateway's BGP ASN.
    bgpAsn: int
    # Name of the VPC customer gateway.
    name: str
    # The Internet-routable IP address for the customer gateway's outside interface.
    # The address must be static.
    publicIp: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The type of VPN connection that this customer gateway supports (ipsec.1 ).
    type: str
class SNSTopicOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Amazon Resource Name (ARN) of the SNS topic. This is set by NixOps.
    arn: str
    # Display name of the topic
    displayName: Optional[str]
    # Name of the SNS topic.
    name: str
    # Policy to apply to the SNS topic.
    policy: str
    # AWS region.
    region: str
    # List of subscriptions to apply to the topic.
    subscriptions: List[NixOpsUnknown[Literal['submodule']]]
class VPCSubnetOptions(nixops.resources.ResourceOptions):
    # The CIDR block for the VPC subnet
    cidrBlock: str
    # The IPv6 network range for the subnet, in CIDR notation.
    # The subnet size must use a /64 prefix length.
    ipv6CidrBlock: Optional[str]
    # Indicates whether instances launched into the subnet should be assigned
    # a public IP in launch. Default is false.
    mapPublicIpOnLaunch: bool
    # Name of the subnet VPC.
    name: str
    # The VPC subnet id generated from AWS. This is set by NixOps
    subnetId: str
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The ID of the VPC where the subnet will be created
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
    # The availability zone for the VPC subnet.
    # By default AWS selects one for you.
    zone: str
class ElasticIPOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # The elastic IP address, set by NixOps.
    address: str
    # AWS region.
    region: str
    # Whether to allocate the address for use with instances in a VPC.
    vpc: bool
class VPCNatGatewayOptions(nixops.resources.ResourceOptions):
    # The allocation ID of the elastic IP address.
    allocationId: Union[str, NixOpsRef[Literal['elastic-ip']]]
    # Name of the VPC NAT gateway.
    name: str
    # The ID of the VPC subnet where the NAT gateway will be created
    subnetId: Union[str, NixOpsRef[Literal['vpc-subnet']]]
class S3BucketOptions(nixops.resources.ResourceOptions):
    # The AWS Access Key ID.
    accessKeyId: str
    # Amazon Resource Name (ARN) of the S3 bucket. This is set by NixOps.
    arn: str
    # The JSON lifecycle management string to apply to the bucket.
    lifeCycle: str
    # Name of the S3 bucket.
    name: str
    # If set to true <command>nixops destroy</command> won't delete the bucket
    # on destroy.
    persistOnDestroy: bool
    # The JSON Policy string to apply to the bucket.
    policy: str
    # Amazon S3 region.
    region: str
    # Whether to enable S3 versioning or not. Valid values are 'Enabled' or 'Suspended'
    versioning: Union[Literal["Suspended"], Literal["Enabled"]]
class VPCDhcpOptionsOptions(nixops.resources.ResourceOptions):
    # If you're using AmazonProvidedDNS in us-east-1, specify ec2.internal.
    # If you're using another region specify region.compute.internal (e.g
    # ap-northeast-1.compute.internal). Otherwise specify a domain name e.g
    # MyCompany.com. This value is used to complete unqualified DNS hostnames.
    domainName: Optional[str]
    # The IP addresses of up to 4 domain name servers, or AmazonProvidedDNS.
    domainNameServers: Optional[List[str]]
    # Name of the DHCP options set.
    name: str
    # The IP addresses of up to 4 NetBIOS name servers.
    netbiosNameServers: Optional[List[str]]
    # The NetBIOS node type (1,2,4 or 8).
    netbiosNodeType: Optional[int]
    # The IP addresses of up to 4 Network Time Protocol (NTP) servers.
    ntpServers: Optional[List[str]]
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The ID of the VPC used to associate the DHCP options to.
    vpcId: Union[str, NixOpsRef[Literal['vpc']]]
