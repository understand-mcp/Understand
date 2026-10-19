"""Legacy module kept to exercise cleanup and comparison defects."""

import os


def read_config(path):
    handle = open(path)
    data = handle.read()
    if not data:
        return {}
    return {'data': data}


def safe_read_config(path):
    if not os.path.exists(path):
        return {}
    with open(path) as handle:
        return {'data': handle.read()}
