#!/usr/bin/env python

from eapdump import parse_eapol_hexdump
from pydantic import BaseModel
import re

class Line(BaseModel):
    ts: float
    msg: BaseModel

re_eap_ts = re.compile("^([\d\.]+): (.*)")
re_eap_hexdump = re.compile("(RX|TX) EAPOL - hexdump\(len=(\d+)\): ([a-f\d\s]+)")

def parse_wpasup_log_line(line, verbosity=0) -> dict:
    r_ts = re_eap_ts.match(line)
    if r_ts:
        ts = r_ts.group(1)
        msg = r_ts.group(2)
        r_msg = re_eap_hexdump.match(msg)
        if r_msg:
            dir = r_msg.group(1)
            len = r_msg.group(2)
            data = r_msg.group(3)
            if verbosity:
                print("===")
                print("#", ts, dir, len)
            parsed = parse_eapol_hexdump(data, verbosity)
        else:
            parsed = BaseModel()
        return Line(ts=ts, msg=parsed)
    else:
        return None

if __name__ == "__main__":
    import argparse
    import sys
    import json
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", action="store", dest="log_file")
    ap.add_argument("-o", action="store", dest="output_file")
    ap.add_argument("-v", action="append_const", default=[], const=1,
                    dest="_verbosity")
    ap.add_argument("--graph", action="store_true", dest="graph")
    ap.add_argument("--test", action="store_true", dest="test")
    opt = ap.parse_args()
    verbosity = len(opt._verbosity)

    if opt.test:
        ret = parse_wpasup_log_line(
            "1673167573.015110: RX EAPOL - hexdump(len=9): 02 00 00 05 01 2b 00 05 01",
            verbosity=verbosity
            )
        print(json.dumps(ret.dict(), indent=4))
    elif opt.graph:
        pass
    else:
        # input file
        if opt.log_file == "-":
            fd = sys.stdin
        elif opt.log_file:
            fd = open(opt.log_file)
        else:
            raise ValueError("ERROR: log_file must be specified.")
        # output file
        if opt.output_file and opt.output_file != "-":
            fd_out = open(opt.output_file, "w")
        else:
            fd_out = sys.stdout
        # parsing
        obj = []
        for line in fd:
            ret = parse_wpasup_log_line(line, verbosity)
            if ret and len(ret.msg.dict()):
                obj.append(ret.dict())
        if obj:
            json.dump(obj, fd_out, indent=4)
