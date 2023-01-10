"""
1673167573.015110: RX EAPOL - hexdump(len=9): 02 00 00 05 01 2b 00 05 01
"""

import re
import argparse
re_eap_hexdump = re.compile("(.*)(RX|TX) EAPOL - hexdump\(len=(\d+)\): ([a-f\d\s]+)")

def com_int(vs):
    if isinstance(vs, list):
        return int("".join(vs), 16)
    return int(vs, 16)

class tv():
    v = None
    t = ""
    def __init__(self, v, t=""):
        self.v = v
        self.t = "UNKNOWN" if t is None else t
    def __str__(self):
        return f"{self.t} ({self.v})"

def parse_eapol(data, verbose=False):
    """
    EAPOL parser
    """
    def eapol_type(vs):
        v2t_map = {
                0: "EAP Packet",
                1: "Start",
                2: "Logoff",
                3: "Key",
                4: "ASF Alert",
                }
        v = com_int(vs)
        t = v2t_map.get(v)
        return tv(v, t)
    p = type("EAPOL", (), {
        "ver": com_int(data[0]),
        "type": eapol_type(data[1]),
        "len": com_int(data[2:4]),
        "body": data[4:], # str
        })
    if verbose:
        print(f"## EAPOL")
        print(f"- Version: {p.ver}")
        print(f"- Type: {p.type}")
        print(f"- Length: {p.len}")
        print(f"- Body: {p.body}")
    return p

def parse_eap(data, verbose=False):
    """
    EAP parser
    """
    def eap_type(vs):
        v2t_map = {
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
        v = com_int(vs)
        t = v2t_map.get(v)
        return tv(v, t)
    def eap_code(vs):
        v2t_map = {
                1: "Request",
                2: "Response",
                3: "Success",
                4: "Failure",
                }
        v = com_int(vs)
        t = v2t_map.get(v)
        return tv(v, t)
    # EAP Header
    p = type("EAP", (), {
        "code": eap_code(data[0]),
        "id": data[1],
        "len": com_int(data[2:4]),
    })
    if p.len > 4:
        p.type = eap_type(data[4])
        p.data = data[5:]
    if verbose:
        print(f"## EAP")
        print(f"- Code: {p.code}")
        print(f"- Identifier: {p.id}")
        print(f"- Length: {p.len}")
        if p.len > 4:
            print(f"- Type: {p.type}")
            print(f"- Data: {p.data}")
    return p

def parse_eapol_hexdump(payload):
    """
        "02 00 ..."
    """
    d = payload.split()
    eapol = parse_eapol(d, verbose=True)
    if eapol.type.v != 0:
        return
    eap = parse_eap(eapol.body, verbose=True)

ap = argparse.ArgumentParser()
ap.add_argument("log_file")
opt = ap.parse_args()

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
        print("===")
        print("#", ts, dir, len)
        parse_eapol_hexdump(r.group(4))
