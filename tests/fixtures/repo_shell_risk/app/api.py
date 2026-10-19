"""HTTP entry points."""

import subprocess

from app.service import run_command, load_user
from app.db import lookup


def handle_ping(request):
    host = request.args.get('host', 'localhost')
    subprocess.call('ping -c 1 ' + host, shell=True)
    return {'ok': True}


def handle_safe_ping(request):
    host = request.args.get('host', 'localhost')
    if host not in ALLOWED_HOSTS:
        return {'error': 'blocked'}
    return run_command('ping', host)


ALLOWED_HOSTS = ('localhost', 'example.com')


def handle_profile(request):
    user_id = request.args.get('id')
    return lookup(user_id)
