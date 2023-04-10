import re

# #define WLAN_EID_CF_PARAMS 4
re_h = re.compile("#define WLAN_EID_([^\s]+)\s+(\d+)")

fmt = """\
    {{
        "id": {eid},
        "name": "{name}",
        "parser": pr_base,
    }},
"""

print("element_list = [")
with open("ieee802_11_defs.h") as fd:
    for line in fd:
        if r := re_h.match(line):
            print(fmt.format(**{"eid":r.group(2), "name":r.group(1)}),
                  end="")
print("]")

