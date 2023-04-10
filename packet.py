from pydantic import BaseModel, Field

class Packet(BaseModel):
    _name: str
    _hexstr: str
    type: str = Field("packet", const=True)
    packet: list[BaseModel]

