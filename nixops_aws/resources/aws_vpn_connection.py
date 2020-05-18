# -*- coding: utf-8 -*-

import botocore
from nixops.state import StateDict
from nixops.diff import Handler
import nixops.util
import nixops.resources
from nixops_aws.resources.ec2_common import EC2CommonState
import nixops_aws.ec2_utils
from typing import Union, Dict
from typing_extensions import Literal
from nixops_aws.types import NixOpsRef

class AWSVPNConnectionOptions(nixops.resources.ResourceOptions):
    # The ID of the customer gateway.
    customerGatewayId: Union[str, NixOpsRef[Literal['vpc-customer-gateway']]]
    # Name of the AWS VPN connection.
    name: str
    # Indicates whether the VPN connection uses static routes only.
    # Static routes must be used for devices that don't support BGP.
    staticRoutesOnly: bool
    # Tags assigned to the instance.  Each tag name can be at most
    # 128 characters, and each tag value can be at most 256
    # characters.  There can be at most 10 tags.
    tags: Dict[str,str]
    # The ID of the VPN gateway.
    vpnGatewayId: Union[str, NixOpsRef[Literal['aws-vpn-gateway']]]

class AWSVPNConnectionDefinition(nixops.resources.ResourceDefinition):
    """Definition of an AWS VPN connection."""
    config: AWSVPNConnectionOptions

    @classmethod
    def get_type(cls):
        return "aws-vpn-connection"

    @classmethod
    def get_resource_type(cls):
        return "awsVPNConnections"

    def show_type(self):
        return "{0}".format(self.get_type())


class AWSVPNConnectionState(nixops.resources.DiffEngineResourceState[AWSVPNConnectionDefinition], EC2CommonState):
    """State of a AWS VPN gateway."""

    state = nixops.util.attr_property(
        "state", nixops.resources.DiffEngineResourceState.MISSING, int
    )
    access_key_id = nixops.util.attr_property("accessKeyId", None)
    _reserved_keys = EC2CommonState.COMMON_EC2_RESERVED + ["vpnConnectionId"]

    def __init__(self, depl, name, id):
        nixops.resources.DiffEngineResourceState.__init__(self, depl, name, id)
        self._state = StateDict(depl, id)
        self.handle_create_vpn_conn = Handler(
            ["region", "vpnGatewayId", "customerGatewayId", "staticRoutesOnly"],
            handle=self.realize_create_vpn_conn,
        )
        self.handle_tag_update = Handler(
            ["tags"],
            after=[self.handle_create_vpn_conn],
            handle=self.realize_update_tag,
        )

    @classmethod
    def get_type(cls):
        return "aws-vpn-connection"

    def show_type(self):
        s = super(AWSVPNConnectionState, self).show_type()
        if self._state.get("region", None):
            s = "{0} [{1}]".format(s, self._state["region"])
        return s

    @property
    def resource_id(self):
        return self._state.get("vpnConnectionId", None)

    def prefix_definition(self, attr):
        return {("resources", "awsVPNConnections"): attr}

    def get_defintion_prefix(self):
        return "resources.awsVPNConnections."

    def create_after(self, resources, defn):
        return {
            r
            for r in resources
            if isinstance(
                r, nixops_aws.resources.vpc_customer_gateway.VPCCustomerGatewayState
            )
            or isinstance(r, nixops_aws.resources.aws_vpn_gateway.AWSVPNGatewayState)
        }

    def realize_create_vpn_conn(self, allow_recreate):
        config = self.get_defn()

        if self.state == self.UP:
            if not allow_recreate:
                raise Exception(
                    "vpn connection {} definition changed and it needs to be recreated"
                    " use --allow-recreate if you want to create a new one".format(
                        self._state["vpnConnectionId"]
                    )
                )
            self.warn("vpn connection definition changed, recreating ...")
            self._destroy()

        self._state["region"] = config["region"]
        customer_gtw_id = config["customerGatewayId"]
        if customer_gtw_id.startswith("res-"):
            res = self.depl.get_typed_resource(
                customer_gtw_id[4:].split(".")[0], "vpc-customer-gateway"
            )
            customer_gtw_id = res._state["customerGatewayId"]

        vpn_gateway_id = config["vpnGatewayId"]
        if vpn_gateway_id.startswith("res-"):
            res = self.depl.get_typed_resource(
                vpn_gateway_id[4:].split(".")[0], "aws-vpn-gateway"
            )
            vpn_gateway_id = res._state["vpnGatewayId"]

        self.log(
            "creating vpn connection between customer gateway {0} and vpn gateway {1}".format(
                customer_gtw_id, vpn_gateway_id
            )
        )
        vpn_connection = self.get_client().create_vpn_connection(
            CustomerGatewayId=customer_gtw_id,
            VpnGatewayId=vpn_gateway_id,
            Type="ipsec.1",
            Options={"StaticRoutesOnly": config["staticRoutesOnly"]},
        )

        vpn_conn_id = vpn_connection["VpnConnection"]["VpnConnectionId"]
        with self.depl._db:
            self.state = self.UP
            self._state["vpnConnectionId"] = vpn_conn_id
            self._state["vpnGatewayId"] = vpn_gateway_id
            self._state["customerGatewayId"] = customer_gtw_id
            self._state["staticRoutesOnly"] = config["staticRoutesOnly"]

    def realize_update_tag(self, allow_recreate):
        config = self.get_defn()
        tags = config["tags"]
        tags.update(self.get_common_tags())
        self.get_client().create_tags(
            Resources=[self._state["vpnConnectionId"]],
            Tags=[{"Key": k, "Value": tags[k]} for k in tags],
        )

    def _destroy(self):
        if self.state == self.UP:
            self.log(
                "deleting vpn connection {}".format(self._state["vpnConnectionId"])
            )
            try:
                self.get_client().delete_vpn_connection(
                    VpnConnectionId=self._state["vpnConnectionId"]
                )
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "InvalidVpnConnectionID.NotFound":
                    self.warn(
                        "vpn connection {} was already deleted".format(
                            self._state["vpnConnectionId"]
                        )
                    )
                else:
                    raise e

        with self.depl._db:
            self.state = self.MISSING
            self._state["vpnConnectionId"] = None
            self._state["vpnGatewayId"] = None
            self._state["customerGatewayId"] = None
            self._state["staticRoutesOnly"] = None

    def destroy(self, wipe=True):
        self._destroy()
        return True
