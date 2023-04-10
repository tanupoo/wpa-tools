from pydantic import BaseModel, Field
from typing import Optional, Union
from packet import Packet

class IE_Base(BaseModel):
    name: str
    eid: int
    length: int
    data: list[int]

    """
    class Config:
        json_encoders = {
            # custom output conversion for your type
            MongoId: lambda mid: str(mid)
        }
    """

    def dict(self, **kwargs):
        output = super().dict(**kwargs)
        for k,v in output.items():
            if k == "data":
                output[k] = " ".join([ f"{_:02x}" for _ in self.data])
        return output

class IE_SSID(IE_Base):
    ssid: str

class IE_Country(IE_Base):
    country: str
    channel_1st: int
    nb_channels: int
    max_tx_power: int

def get_payload(data, offset):
    offset += 1
    length = data[offset]
    offset += 1
    payload = data[offset:offset+length]
    return payload, length, offset+length

def pr_roaming_consortium(hdl, data, offset):
    payload, length, offset = get_payload(data, offset)
    #print("xxx", [hex(i) for i in payload])
    return offset, IE_Base(name=f"IE {hdl['name']}", eid=hdl["id"],
                          length=length, data=payload)

def pr_country(hdl, data, offset):
    payload, length, offset = get_payload(data, offset)
    country = "".join([chr(a) for a in payload[0:3]])
    return offset, IE_Country(name=f"IE {hdl['name']}", eid=hdl["id"],
                              length=length, data=payload,
                              country=country,
                              channel_1st=int(payload[3]),
                              nb_channels=int(payload[4]),
                              max_tx_power=int(payload[5]))

def pr_supported_rates(hdl, data, offset):
    payload, length, offset = get_payload(data, offset)
    return offset, IE_Base(name=f"IE {hdl['name']}", eid=hdl["id"],
                          length=length, data=payload)

def pr_ssid(hdl, data, offset):
    payload, length, offset = get_payload(data, offset)
    ssid = "".join([chr(a) for a in payload])
    return offset, IE_SSID(name=f"IE {hdl['name']}", eid=hdl["id"],
                          length=length, data=payload,
                          ssid=ssid)

def pr_base(hdl, data, offset):
    payload, length, offset = get_payload(data, offset)
    return offset, IE_Base(name=f"IE {hdl['name']}", eid=hdl["id"],
                          length=length, data=payload)


element_list = [
    {
        "id": 0,
        "name": "SSID",
        "parser": pr_ssid,
    },
    {
        "id": 1,
        "name": "Supported Rates",
        "parser": pr_supported_rates,
    },
    {
        "id": 2,
        "name": "FH Parameter Set",
        "parser": pr_base,
    },
    {
        "id": 3,
        "name": "DS Parameter Set",
        "parser": pr_base,
    },
    {
        "id": 4,
        "name": "CF Parameter Set",
        "parser": pr_base,
    },
    {
        "id": 5,
        "name": "Traffic Indication Map",
        "parser": pr_base,
    },
    {
        "id": 6,
        "name": "IBSS Parameter Set",
        "parser": pr_base,
    },
    {
        "id": 7,
        "name": "Country",
        "parser": pr_country,
    },
    {
        "id": 16,
        "name": "CHALLENGE",
        "parser": pr_base,
    },
    {
        "id": 32,
        "name": "PWR_CONSTRAINT",
        "parser": pr_base,
    },
    {
        "id": 33,
        "name": "PWR_CAPABILITY",
        "parser": pr_base,
    },
    {
        "id": 34,
        "name": "TPC_REQUEST",
        "parser": pr_base,
    },
    {
        "id": 35,
        "name": "TPC_REPORT",
        "parser": pr_base,
    },
    {
        "id": 36,
        "name": "SUPPORTED_CHANNELS",
        "parser": pr_base,
    },
    {
        "id": 37,
        "name": "CHANNEL_SWITCH",
        "parser": pr_base,
    },
    {
        "id": 38,
        "name": "MEASURE_REQUEST",
        "parser": pr_base,
    },
    {
        "id": 39,
        "name": "MEASURE_REPORT",
        "parser": pr_base,
    },
    {
        "id": 40,
        "name": "QUITE",
        "parser": pr_base,
    },
    {
        "id": 41,
        "name": "IBSS_DFS",
        "parser": pr_base,
    },
    {
        "id": 42,
        "name": "ERP_INFO",
        "parser": pr_base,
    },
    {
        "id": 45,
        "name": "HT_CAP",
        "parser": pr_base,
    },
    {
        "id": 48,
        "name": "RSN",
        "parser": pr_base,
    },
    {
        "id": 50,
        "name": "EXT_SUPP_RATES",
        "parser": pr_base,
    },
    {
        "id": 54,
        "name": "MOBILITY_DOMAIN",
        "parser": pr_base,
    },
    {
        "id": 55,
        "name": "FAST_BSS_TRANSITION",
        "parser": pr_base,
    },
    {
        "id": 56,
        "name": "TIMEOUT_INTERVAL",
        "parser": pr_base,
    },
    {
        "id": 57,
        "name": "RIC_DATA",
        "parser": pr_base,
    },
    {
        "id": 61,
        "name": "HT_OPERATION",
        "parser": pr_base,
    },
    {
        "id": 62,
        "name": "SECONDARY_CHANNEL_OFFSET",
        "parser": pr_base,
    },
    {
        "id": 68,
        "name": "WAPI",
        "parser": pr_base,
    },
    {
        "id": 69,
        "name": "TIME_ADVERTISEMENT",
        "parser": pr_base,
    },
    {
        "id": 72,
        "name": "20_40_BSS_COEXISTENCE",
        "parser": pr_base,
    },
    {
        "id": 73,
        "name": "20_40_BSS_INTOLERANT",
        "parser": pr_base,
    },
    {
        "id": 74,
        "name": "OVERLAPPING_BSS_SCAN_PARAMS",
        "parser": pr_base,
    },
    {
        "id": 76,
        "name": "MMIE",
        "parser": pr_base,
    },
    {
        "id": 84,
        "name": "SSID_LIST",
        "parser": pr_base,
    },
    {
        "id": 90,
        "name": "BSS_MAX_IDLE_PERIOD",
        "parser": pr_base,
    },
    {
        "id": 91,
        "name": "TFS_REQ",
        "parser": pr_base,
    },
    {
        "id": 92,
        "name": "TFS_RESP",
        "parser": pr_base,
    },
    {
        "id": 93,
        "name": "WNMSLEEP",
        "parser": pr_base,
    },
    {
        "id": 98,
        "name": "TIME_ZONE",
        "parser": pr_base,
    },
    {
        "id": 101,
        "name": "LINK_ID",
        "parser": pr_base,
    },
    {
        "id": 107,
        "name": "INTERWORKING",
        "parser": pr_base,
    },
    {
        "id": 108,
        "name": "ADV_PROTO",
        "parser": pr_base,
    },
    {
        "id": 111,
        "name": "ROAMING_CONSORTIUM",
        "parser": pr_roaming_consortium,
    },
    {
        "id": 127,
        "name": "EXT_CAPAB",
        "parser": pr_base,
    },
    {
        "id": 156,
        "name": "CCKM",
        "parser": pr_base,
    },
    {
        "id": 191,
        "name": "VHT_CAP",
        "parser": pr_base,
    },
    {
        "id": 192,
        "name": "VHT_OPERATION",
        "parser": pr_base,
    },
    {
        "id": 193,
        "name": "VHT_EXTENDED_BSS_LOAD",
        "parser": pr_base,
    },
    {
        "id": 194,
        "name": "VHT_WIDE_BW_CHSWITCH",
        "parser": pr_base,
    },
    {
        "id": 195,
        "name": "VHT_TRANSMIT_POWER_ENVELOPE",
        "parser": pr_base,
    },
    {
        "id": 196,
        "name": "VHT_CHANNEL_SWITCH_WRAPPER",
        "parser": pr_base,
    },
    {
        "id": 197,
        "name": "VHT_AID",
        "parser": pr_base,
    },
    {
        "id": 198,
        "name": "VHT_QUIET_CHANNEL",
        "parser": pr_base,
    },
    {
        "id": 199,
        "name": "VHT_OPERATING_MODE_NOTIFICATION",
        "parser": pr_base,
    },
    {
        "id": 221,
        "name": "VENDOR_SPECIFIC",
        "parser": pr_base,
    },
]

elm_xxx = {
        "id": 999,
        "name": "Unknown",
        "parser": pr_base,
    }

def parse_ieee80211ie(data: list[int], verbosity=0):
    elm_map = {}
    for i in element_list:
        elm_map.update({i["id"]: i})
    #
    ieset = []
    data_len = len(data)
    offset = 0
    while offset < data_len:
        eid = data[offset]
        h = elm_map.get(eid)
        if h is not None:
            offset, elm = h["parser"](h, data, offset)
            if verbosity:
                print(f"## {elm.eid}: {elm.name}")
                print(f"- Length: {elm.length}")
                print(elm)
        else:
            offset, elm = pr_base(elm_xxx, data, offset)
            if verbosity:
                print(f"## {eid}: Unknown")
                print(elm)
                #print(f"- Data: {[hex(i) for i in elm.data]}")
        ieset.append(elm)
    return ieset

def parse_ieee80211ie_hexdump(ts, keys, verbosity=0):
    """
    ts: timestamp, str
    keys: re.group
    verbosity:
        "02 00 ..."
    """
    len = keys(1)
    payload = keys(2)
    if verbosity > 1:
        print("===")
        print("#", ts, len, payload)
    d = [int(n,16) for n in payload.split()]
    obj = parse_ieee80211ie(d, verbosity=verbosity)
    return Packet(_name="IE", _hexstr=payload, packet=obj)

if __name__ == "__main__":
    test_payloads = [
        #1680313868.427508: IEs - hexdump(len=328)
        """
        00 08 63 69 74 79 72 6f 61 6d
        01 08 8c 12 98 24 b0 48 60 6c
        03 01 70
        07 0a 4a 50 20 24 08 17 64 0a 1e 00
        20 01 00
        23 02 11 00
        dd 05 50 6f 9a 10 20
        dd 08 50 6f 9a 09 0a 01 00 01
        0b 05 03 00 05 00 00
        46 05 73 d0 00 00 0c
        2d 1a ef 09 03 ff ff 00 00 00
              00 00 00 00 00 00 00 01
              00 00 00 00 00 00 00 00 00 00
        3d 16 70 07 04 00 00 00 00 00
              00 00 00 00 00 00 00 00
              00 00 00 00 00 00
        4a 0e 14 00 0a 00 2c 01 c8 00 14 00 05 00 19 00
        7f 0a 05 00 08 80 00 40 00 40 00 40
        bf 0c b2 f9 89 33 fa ff 00 00 fa ff 00 00
        c0 05 01 6a 00 fc ff
        c3 04 02 3c 3c 3c
        ff 1d 23 0d 01 08 1a 40 00 04
              70 0c 80 1f c1 83 04 01
              08 00 fa ff fa ff 79 1c c7 71 1c c7 71
        ff 07 24 f4 3f 00 31 fc ff
        ff 02 27 03
        ff 0e 26 00 08 a9 ff 2f a9 ff 45 75
        ff 65 75 ff dd 18 00 50 f2 02 01 01 80 00 03 a4 00 00 27 a4 00 00 42 43 5e
        00 62 32 2f 00 dd 09 00 03 7f 01 01 00 00 ff 7f 30 14 01 00 00 0f ac 04 01
        00 00 0f ac 04 01 00 00 0f ac 01 00 00 6b 01 13 6c 02 7f 00 6f 0a 00 35 5a
        03 ba 00 00 00 40 96 dd 08 00 13 92 01 00 01 05 18
        """
        ,
        #1680313868.427891: Beacon IEs - hexdump(len=351): 
        """
        00 08 63 69 74 79 72 6f 61
        6d 01 08 8c 12 98 24 b0 48 60 6c 03 01 70 05 04 00 01 00 00 07 0a 4a 50 20
        24 08 17 64 0a 1e 00 20 01 00 23 02 11 00 0b 05 03 00 05 00 00 6b 01 13 6c
        02 7f 00 6f 0a 00 35 5a 03 ba 00 00 00 40 96 46 05 73 d0 00 00 0c 2d 1a ef
        09 03 ff ff 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00
        3d 16 70 07 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4a
        0e 14 00 0a 00 2c 01 c8 00 14 00 05 00 19 00 7f 0a 05 00 08 80 00 40 00 40
        00 40 bf 0c b2 f9 89 33 fa ff 00 00 fa ff 00 00 c0 05 01 6a 00 fc ff c3 04
        02 3c 3c 3c ff 1d 23 0d 01 08 1a 40 00 04 70 0c 80 1f c1 83 04 01 08 00 fa
        ff fa ff 79 1c c7 71 1c c7 71 ff 07 24 f4 3f 00 31 fc ff ff 02 27 03 ff 0e
        26 00 08 a9 ff 2f a9 ff 45 75 ff 65 75 ff dd 18 00 50 f2 02 01 01 80 00 03
        a4 00 00 27 a4 00 00 42 43 5e 00 62 32 2f 00 dd 09 00 03 7f 01 01 00 00 ff
        7f 30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 01 00 00 dd 08
        00 13 92 01 00 01 05 00 dd 0f 00 1f 41 04 04 2d d4 1f 5f 05 04 45 58 af 61
        dd 05 50 6f 9a 10 20 dd 08 50 6f 9a 09 0a 01 00 01
        """
    ]
    for payload in test_payloads:
        print("----")
        parse_ieee80211ie_hexdump(0, payload, 1)
