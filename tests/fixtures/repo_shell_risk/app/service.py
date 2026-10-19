"""Service layer between HTTP and the database."""

import subprocess


def run_command(program, argument):
    return subprocess.check_output([program, '-c', '1', argument])


def load_user(user_id):
    return {'id': user_id}
