"""
1673167573.015110: RX EAPOL - hexdump(len=9): 02 00 00 05 01 2b 00 05 01
"""

from pydantic import BaseModel
from typing import List, Optional
import re
import argparse

re_eap_hexdump = re.compile("(.*)(RX|TX) EAPOL - hexdump\(len=(\d+)\): ([a-f\d\s]+)")

class ValText(BaseModel):
    Value: int
    Text: str

    def __str__(self):
        return f"{self.Value} ({self.Text})"

class EAPOL(BaseModel):
    Version: int
    Type: ValText
    Length: int
    Body: List[str]

class EAP(BaseModel):
    Code: ValText
    Identifier: int
    Length: int
    Type: Optional[ValText]
    Data: Optional[List[str]]

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
            Version=com_int(data[0]),
            Type=com_vt(data[1], type_map),
            Length=com_int(data[2:4]),
            Body=data[4:]
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
            Code=com_vt(data[0], code_map),
            Identifier=com_int(data[1]),
            Length=com_int(data[2:4]),
            )
    if p.Length > 4:
        p.Type = com_vt(data[4], type_map)
        if p.Type.Text == "Identity":
            p.Data = "".join([chr(int(i,16)) for i in data[5:]])
        else:
            p.Data = data[5:]
    if verbosity:
        print(f"## EAP")
        print(f"- Code: {p.Code}")
        print(f"- Identifier: {p.Identifier}")
        print(f"- Length: {p.Length}")
        if p.Length > 4:
            print(f"- Type: {p.Type}")
            print(f"- Data: {p.Data}")
    return p

def parse_eapol_hexdump(payload, verbosity=0):
    """
        "02 00 ..."
    """
    d = payload.split()
    eapol = parse_eapol(d, verbosity=verbosity)
    if eapol.Type.Value != 0:
        return eapol
    eap = parse_eap(eapol.Body, verbosity=verbosity)

ap = argparse.ArgumentParser()
ap.add_argument("log_file")
ap.add_argument("-v", action="append_const", default=[], const=1,
                dest="_verbosity")
opt = ap.parse_args()

opt.verbosity = len(opt._verbosity)

if opt.log_file == "-":
    fd = sys.stdin
else:
    fd = open(opt.log_file)

#line = "1673167573.015110: RX EAPOL - hexdump(len=9): 02 00 00 05 01 2b 00 05 01"

for line in fd:
    r = re_eap_hexdump.match(line)
    if r:
        ts = r.group(1)
        dir = r.group(2)
        len = r.group(3)
        if opt.verbosity:
            print("===")
            print("#", ts, dir, len)
        parse_eapol_hexdump(r.group(4), opt.verbosity)
