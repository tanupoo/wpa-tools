from pydantic import BaseModel, Field
from typing import Optional, Union

class ValText(BaseModel):
    Value: int
    Text: str

    def __str__(self):
        return f"{self.Value} ({self.Text})"

class EAPOL(BaseModel):
    packet_name: str
    packet_hexstr: str
    Version: int
    Type: ValText
    Length: int
    Body: str

class EAP(BaseModel):
    packet_name: str
    packet_hexstr: str
    Code: ValText
    Identifier: int
    Length: int
    Type: Optional[ValText]
    Data: Optional[str]

class Packet(BaseModel):
    _name: str
    _hexstr: str
    type: str = Field("packet", const=True)
    packet: list[Union[EAPOL, EAP]]

def com_int(vs):
    if isinstance(vs, list):
        return int("".join(vs), 16)
    return int(vs, 16)

def com_vt(vs: str, vtmap: dict):
    v = com_int(vs)
    t = vtmap.get(v)
    return ValText(
            Value=v,
            Text="UNKNOWN" if t is None else t
            )

def parse_eapol(data, verbosity=0):
    # EAPOL parser
    type_map = {
            0: "EAP Packet",
            1: "Start",
            2: "Logoff",
            3: "Key",
            4: "ASF Alert",
            }
    p = EAPOL(
            packet_name="EAPOL",
            packet_hexstr=" ".join(data),
            Version=com_int(data[0]),
            Type=com_vt(data[1], type_map),
            Length=com_int(data[2:4]),
            Body=" ".join(data[4:])
        )
    if verbosity:
        print(f"## EAPOL")
        print(f"- Version: {p.Version}")
        print(f"- Type: {p.Type}")
        print(f"- Length: {p.Length}")
        if verbosity > 1:
            print(f"- Body: {p.Body}")
    return p

def parse_eap(data, verbosity=0):
    # EAP parser
    code_map = {
            1: "Request",
            2: "Response",
            3: "Success",
            4: "Failure",
            }
    type_map = {
            1: "Identity",
            2: "Notification",
            3: "NAK",
            4: "MD5-Challenge",
            5: "OTP",
            6: "GTC",
            13: "EAP-TLS",
            21: "EAP-TTLS",
            25: "EAP-PEAP",
            }
    # EAP Header
    p = EAP(
            packet_name="EAP",
            packet_hexstr=" ".join(data),
            Code=com_vt(data[0], code_map),
            Identifier=com_int(data[1]),
            Length=com_int(data[2:4]),
            )
    if p.Length > 4:
        p.Type = com_vt(data[4], type_map)
        if p.Type.Text == "Identity":
            p.Data = "".join([chr(int(i,16)) for i in data[5:]])
        else:
            p.Data = " ".join(data[5:])
    if verbosity:
        print(f"## EAP")
        print(f"- Code: {p.Code}")
        print(f"- Identifier: {p.Identifier}")
        print(f"- Length: {p.Length}")
        if p.Length > 4:
            print(f"- Type: {p.Type}")
            print(f"- Data: {p.Data}")
    return p

def parse_eapol_hexdump(ts, keys, verbosity=0):
    """
    ts: timestamp, str
    keys: re.group
    verbosity:
        "02 00 ..."
    """
    dir = keys(1)
    len = keys(2)
    payload = keys(3)
    if verbosity:
        print("===")
        print("#", ts, dir, len)
    d = payload.split()
    eapol = parse_eapol(d, verbosity=verbosity)
    if eapol.Type.Value != 0:
        return Packet(_name="Frame", _hexstr=payload, packet=[ eapol ])
    eap = parse_eap(eapol.Body.split(), verbosity=verbosity)
    return Packet(_name="Frame", _hexstr=payload, packet=[ eapol, eap ])
