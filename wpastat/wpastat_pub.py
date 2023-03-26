from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired
from shlex import split as shlex_split
import re
import time
import json

import paho.mqtt.client as mqtt
import argparse
import time

def on_connect(client, userdata, flags, rc, properties=None):
    global connected
    connected = True
    print("Connected with status:", client, userdata, flags, rc, properties)

def on_disconnect(client, userdata, rc, properties=None):
    global connected
    connected = False
    print("Disconnected:", client, userdata, rc, properties)

def on_message(client, userdata, message):
    # for subscriber.
    print("Received:", client, userdata, message)

def on_publish(client, userdata, mid):
    print("Published:", client, userdata, mid)

def on_log(mqttc, obj, level, string):
    print(string)

def parse(otext):
    res = {}
    for line in otext.split("\n"):
        if r := re.match("ssid=(.+)", line):
            res.update({"ssid": r.group(1)})
        elif r := re.search("wpa_state=(.+)", line):
            res.update({"wpa_state": r.group(1)})
        elif r := re.search("key_mgmt=(.+)", line):
            res.update({"key_mgmt": r.group(1)})
    return res


if __name__ == "__main__":
    from argparse import ArgumentParser
    ap = ArgumentParser()
    ap.add_argument("-s", action="store", dest="broker_addr",
                    default="127.0.0.1",
                    help="specify a server name or IP address to be bound.")
    ap.add_argument("-p", action="store", dest="broker_port",
                    type=int, default=1883,
                    help="specify the port number to be listened.")
    ap.add_argument("-d", action="store_true", dest="debug",
                    help="enable debug mode.")
    opt = ap.parse_args()

    connected = False
    print(f"Broker: {opt.broker_addr} {opt.broker_port}")
    client = mqtt.Client()
    #client.username_pw_set("pub1", "hoge")
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    client.on_log = on_log
    client.connect(opt.broker_addr, opt.broker_port, 60)
    client.loop_start()

    print("connecting.", end="")
    while not connected:
        time.sleep(1)
        print(".", end="")

    while True:

        with Popen(shlex_split("sudo wpa_cli status"),
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE,
                universal_newlines=True) as proc:
            try:
                outs, errs = proc.communicate(timeout=3)
            except TimeoutExpired as e:
                print("TimeoutExpired", e)
            else:
                if errs:
                    print("errs=", errs)
                if opt.debug:
                    print("outs:", outs)
                stat_obj = parse(outs)
                if opt.debug:
                    print("stat_obj:", stat_obj)
                client.publish("wpastat", json.dumps(stat_obj), 0)
        time.sleep(1)

