#!/usr/bin/env python

from wpal_parse import Line
import json
from matplotlib import pyplot as plt
from datetime import datetime

state_val = {
    "EAPOL_PAE": [
        "DISCONNECTED",
        "CONNECTING",
        "RESTART",
        "AUTHENTICATING",
        "AUTHENTICATED",
    ],
    "EAPOL_BE": [
        "INITIALIZE",
        "IDLE",
        "TIMEOUT",
        "REQUEST",
        "RESPONSE",
        "RECEIVE",
        "SUCCESS",
    ],
    "EAP": [
        "DISABLED",
        "INITIALIZE",
        "IDLE",
        "RECEIVED",
        "IDENTITY",
        "GET_METHOD",
        "METHOD",
        "SEND_RESPONSE",
        "SUCCESS",
    ],
    "I/F": [
        "INACTIVE",
        "DISCONNECTED",
        "SCANNING",
        "AUTHENTICATING",
        "ASSOCIATING",
        "ASSOCIATED",
        "4WAY_HANDSHAKE",
        "GROUP_HANDSHAKE",
        "COMPLETED",
    ]
}

def find_val(state_type, state_name):
    for i,x in enumerate(state_val[state_type]):
        if x == state_name:
            return i
    else:
        raise ValueError(f"{state_type} {state_name} not found")

def print_registered_state():
    print("\n## STATE REGISTERED")
    for a,b in state_val.items():
        print(f"- {a}")
        for i,c in enumerate(b):
            print(i, c)

def print_existing_state(pel):
    print("\n## STATE USED")
    for a in pel:
        for b in a["states"].keys():
            state_list = set([_["state"] for _ in a["states"][b]])
            print(b, state_list)

def read_log(log_file):
    if log_file == "-":
        fd = sys.stdin
    elif log_file:
        fd = open(log_file)
    #
    vx = {
        "packets": {
            "rx_id": [],
            "tx_id": [],
            "rx_oth": [],
            "tx_oth": [],
            },
        "states": { }
        }
    ts_epoc = 0
    if opt.ts_absolute:
        ts_conv = lambda x_cur, x_epoc: x_cur
    else:
        ts_conv = lambda x_cur, x_epoc: x_cur - x_epoc
    for x in json.load(fd): 
        line = Line.parse_obj(x)
        ts_cur = line.ts
        if ts_epoc == 0:
            ts_epoc = ts_cur    # save ts_epoc only once
        ts = ts_conv(ts_cur, ts_epoc)
        # EAPOL, EAP, Request, Identity
        # EAPOL, EAP, Response, Identity
        # EAPOL, EAP, Request, Other
        # EAPOL, EAP, Response, Other
        #eapol = [x for x in line.msg.packet if x.packet_name == "EAPOL"][0]
        if line.msg.type == "packet":
            eapx = [x for x in line.msg.packet if x.packet_name == "EAP"]
            if eapx:
                eap = eapx[0]
                xpkt = vx["packets"]
                if eap.Code.Text == "Response":
                    if hasattr(eap.Type, "Text") and eap.Type.Text == "Identity":
                        xpkt.setdefault("rx_id", []).append(ts)
                    else:
                        xpkt.setdefault("rx_oth", []).append(ts)
                else:
                    if hasattr(eap.Type, "Text") and eap.Type.Text == "Identity":
                        xpkt.setdefault("tx_id", []).append(ts)
                    else:
                        xpkt.setdefault("tx_oth", []).append(ts)
        elif line.msg.type in [ "EAPOL_PAE", "EAPOL_BE", "EAP", "I/F" ]:
            x2 = vx["states"].setdefault(line.msg.type, [])
            x2.append({"ts": ts, "state": line.msg.state})
        elif line.msg.type == "BSSID":
            print("\n## BSSID", line.msg.state)
    vx.update({"ts_start": datetime.fromtimestamp(ts_epoc)})
    vx.update({"ts_end": datetime.fromtimestamp(ts_cur)})
    return vx

if __name__ == "__main__":
    import argparse
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", action="append", dest="log_files",
                    help="specify a log filename. can use in multiple times.")
    ap.add_argument("-t", action="store", dest="target",
                    type=int, default=None,
                    help="specify the number of the targt. {}".format(
                            [{i,v} for i,v in enumerate(state_val.keys())]))
    ap.add_argument("-a", action="store", dest="alignment",
                    type=float, default=0,
                    help="specify the number of alignment to show the merged graph.")
    ap.add_argument("-T", action="store_true", dest="ts_absolute",
                    help="enable to show absolute timestamp.")
    opt = ap.parse_args()
    if len(opt.log_files) == 0:
        raise ValueError("ERROR: log_file must be specified.")
    print_registered_state()
    #
    pel = []    # Parsed Each Log
    for f in opt.log_files:
        pel.append(read_log(f))
        print("Start TS:", pel[0]["ts_start"])
        print("  End TS:", pel[0]["ts_end"])
    print_existing_state(pel)
    #
    fig = plt.figure(figsize=(24,4))
    ax = fig.add_subplot(1,1,1)

    def add_line(data, vy, color):
        ax.scatter(data, [vy for _ in range(len(data))], color=color)

    for a in pel:
        for i,b in enumerate(a["states"].keys()):
            if opt.target is not None and opt.target != i:
                continue
            x = [_["ts"]+i*opt.alignment for _ in a["states"][b]]
            y = [find_val(b, _["state"]) for _ in a["states"][b]]
            ax.plot(x, y, label=b)

        add_line(a["packets"]["rx_id"], 1, "red")
        add_line(a["packets"]["tx_id"], 2, "black")
        add_line(a["packets"]["rx_oth"], 3, "blue")
        add_line(a["packets"]["tx_oth"], 4, "yellow")

    if opt.target is not None:
        k = state_val[list(state_val.keys())[opt.target]]
        ax.set_yticks(list(range(len(k))), k)

    ax.grid(visible=True, which="major")
    fig.legend()
    fig.tight_layout()
    plt.show()

