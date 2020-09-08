from typing import Sequence
from nixops.resources import ResourceOptions
from typing import Optional


class RDSDbSubnetGroupOptions(ResourceOptions):
    accessKeyId: str
    description: str
    name: str
    region: str
    subnetIds: Sequence[str]
