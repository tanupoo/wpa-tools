#!/usr/bin/env python

from wpal_parse import Line
import json
from matplotlib import pyplot as plt

def read_log(log_file):
    if log_file == "-":
        fd = sys.stdin
    elif log_file:
        fd = open(log_file)
    #
    vx = {
            "tx_id": [],
            "rx_id": [],
            "tx_oth": [],
            "rx_oth": [],
            }
    ts_epoc = 0
    for x in json.load(fd): 
        line = Line.parse_obj(x)
        if ts_epoc == 0:
            ts_epoc = line.ts
        ts = line.ts - ts_epoc
        # EAPOL, EAP, Request, Identity
        # EAPOL, EAP, Response, Identity
        # EAPOL, EAP, Request, Other
        # EAPOL, EAP, Response, Other
        #eapol = [x for x in line.msg.packet if x.packet_name == "EAPOL"][0]
        eapx = [x for x in line.msg.packet if x.packet_name == "EAP"]
        if eapx:
            eap = eapx[0]
            if eap.Code.Text == "Response":
                if hasattr(eap.Type, "Text") and eap.Type.Text == "Identity":
                    vx["rx_id"].append(ts)
                else:
                    vx["rx_oth"].append(ts)
            else:
                if hasattr(eap.Type, "Text") and eap.Type.Text == "Identity":
                    vx["tx_id"].append(ts)
                else:
                    vx["tx_oth"].append(ts)
    return vx

if __name__ == "__main__":
    import argparse
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", action="append", dest="log_files")
    opt = ap.parse_args()
    if len(opt.log_files) == 0:
        raise ValueError("ERROR: log_file must be specified.")
    vxs = []
    for f in opt.log_files:
        vxs.append(read_log(f))
    mx = 0
    for vx in vxs:
        mx = max(mx, int(max(sum(list(vx.values()), []))))
    mx += 10
    #
    def add_line(data, vy, fig, color):
        ax.scatter(data, [vy for _ in range(len(data))], color=color)

    nb_axs = len(vxs)
    fig = plt.figure(figsize=(int(mx/16),2*nb_axs))
    for i,vx in enumerate(vxs):
        ax = fig.add_subplot(nb_axs,1,i+1)
        ax.set_xticks(list(range(0, mx, 10)))
        ax.set_xlim(-10,mx)
        ax.set_ylim(0,5)
        add_line(vx["rx_id"], 1, fig, "red")
        add_line(vx["tx_id"], 2, fig, "black")
        add_line(vx["rx_oth"], 3, fig, "blue")
        add_line(vx["tx_oth"], 4, fig, "yellow")

    fig.tight_layout()
    plt.show()
