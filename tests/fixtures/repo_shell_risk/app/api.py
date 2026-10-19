"""HTTP entry points."""

import subprocess

from app.db import lookup
from app.service import load_user, run_command


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
