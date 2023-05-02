import json
import os

f_name = "dump_info.json"


def get_options():
    if not os.path.isfile(f_name):
        return {}

    with open(f_name, "rt") as fi:
        options = json.load(fi)

    print(f"got options: {json.dumps(options, indent=4)}")
    return options
