from typing import Generic, TypeVar

Type = TypeVar("Type", bound=str)

class NixOpsRef(Generic[Type]):
    pass
