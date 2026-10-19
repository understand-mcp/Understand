"""Generate deterministic fixture repositories for the UNDERSTAND test-suite.

Run from the repository root:  python tools/make_fixtures.py
Every file is written verbatim and no timestamps or random data are involved,
so the fixtures are byte-stable across machines and runs.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

FIXTURES: dict[str, dict[str, str]] = {
    "repo_shell_risk": {
        "README.md": "# fixture: shell risk\n\nDeliberately vulnerable sample used by the test-suite.\n",
        "requirements.txt": "flask==3.0.0\nrequests>=2.31\n",
        "app/__init__.py": "",
        "app/api.py": (
            '"""HTTP entry points."""\n'
            "\n"
            "import subprocess\n"
            "\n"
            "from app.service import run_command, load_user\n"
            "from app.db import lookup\n"
            "\n"
            "\n"
            "def handle_ping(request):\n"
            "    host = request.args.get('host', 'localhost')\n"
            "    subprocess.call('ping -c 1 ' + host, shell=True)\n"
            "    return {'ok': True}\n"
            "\n"
            "\n"
            "def handle_safe_ping(request):\n"
            "    host = request.args.get('host', 'localhost')\n"
            "    if host not in ALLOWED_HOSTS:\n"
            "        return {'error': 'blocked'}\n"
            "    return run_command('ping', host)\n"
            "\n"
            "\n"
            "ALLOWED_HOSTS = ('localhost', 'example.com')\n"
            "\n"
            "\n"
            "def handle_profile(request):\n"
            "    user_id = request.args.get('id')\n"
            "    return lookup(user_id)\n"
        ),
        "app/service.py": (
            '"""Service layer between HTTP and the database."""\n'
            "\n"
            "import subprocess\n"
            "\n"
            "\n"
            "def run_command(program, argument):\n"
            "    return subprocess.check_output([program, '-c', '1', argument])\n"
            "\n"
            "\n"
            "def load_user(user_id):\n"
            "    return {'id': user_id}\n"
        ),
        "app/db.py": (
            '"""Persistence helpers."""\n'
            "\n"
            "import sqlite3\n"
            "\n"
            "\n"
            "def lookup(user_id):\n"
            "    connection = sqlite3.connect('app.db')\n"
            "    cursor = connection.cursor()\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
            "    if cursor.fetchone() is None:\n"
            "        return None\n"
            "    return cursor.fetchone()\n"
        ),
        "app/legacy.py": (
            '"""Legacy module kept to exercise cleanup and comparison defects."""\n'
            "\n"
            "import os\n"
            "\n"
            "\n"
            "def read_config(path):\n"
            "    handle = open(path)\n"
            "    data = handle.read()\n"
            "    if not data:\n"
            "        return {}\n"
            "    return {'data': data}\n"
            "\n"
            "\n"
            "def safe_read_config(path):\n"
            "    if not os.path.exists(path):\n"
            "        return {}\n"
            "    with open(path) as handle:\n"
            "        return {'data': handle.read()}\n"
        ),
        "app/quirks.py": (
            '"""Deliberate bug patterns."""\n'
            "\n"
            "\n"
            "def parse_flag(flag):\n"
            "    if flag = True:\n"
            "        return 'on'\n"
            "    return 'off'\n"
            "\n"
            "\n"
            "def swallow():\n"
            "    try:\n"
            "        return 1 / 0\n"
            "    except:\n"
            "        pass\n"
            "\n"
            "\n"
            "def unreachable():\n"
            "    return 'value'\n"
        ),
        "config/settings.py": (
            '"""Configuration."""\n'
            "\n"
            "DATABASE_URL = 'postgres://user:password@localhost:5432/app'\n"
            "API_TOKEN = 'example-not-a-real-token-0000'\n"
        ),
        "Dockerfile": (
            "FROM python:3.12-slim\n"
            "ENV API_KEY=supersecretvalue123456\n"
            "COPY . /app\n"
            "RUN chmod 777 /app\n"
            "CMD [\"python\", \"-m\", \"app.api\"]\n"
        ),
        "tests/test_api.py": (
            '"""Tests exercise the HTTP layer."""\n'
            "\n"
            "from app.api import handle_ping\n"
            "\n"
            "\n"
            "def test_handle_ping():\n"
            "    assert handle_ping is not None\n"
        ),
    },
    "repo_minimal": {
        "README.md": "# fixture: clean repository\n\nNo defects on purpose.\n",
        "pkg/__init__.py": "",
        "pkg/math.py": (
            '"""Small arithmetic helpers."""\n'
            "\n"
            "\n"
            "def add(left, right):\n"
            "    return left + right\n"
            "\n"
            "\n"
            "def multiply(left, right):\n"
            "    return left * right\n"
        ),
        "pkg/consumer.py": (
            '"""Uses the helpers above."""\n'
            "\n"
            "from pkg.math import add, multiply\n"
            "\n"
            "\n"
            "def total(values):\n"
            "    result = 0\n"
            "    for value in values:\n"
            "        result = add(result, value)\n"
            "    return result\n"
            "\n"
            "\n"
            "def main():\n"
            "    return total([multiply(2, 3), 4])\n"
        ),
    },
    "repo_mixed_content": {
        "README.md": "# fixture: mixed content\n\nBinary, generated, vendored and dynamic constructs.\n",
        "data/blob.bin": "\x00\x01\x02binary\x00\x03",
        "generated/schema_pb2.py": (
            "# @generated by protoc. DO NOT EDIT.\n"
            "import os\n"
            "\n"
            "\n"
            "def generated_helper():\n"
            "    return os.name\n"
        ),
        "vendor/thirdparty.py": (
            '"""Vendored dependency."""\n'
            "\n"
            "\n"
            "def third_party_call():\n"
            "    import os\n"
            "    return os.getcwd()\n"
        ),
        "src/dispatch.py": (
            '"""Dynamic dispatch and reflection."""\n'
            "\n"
            "\n"
            "def run(name, registry):\n"
            "    handler = getattr(registry, name)\n"
            "    return handler()\n"
            "\n"
            "\n"
            "def call_via_name(module_name, function_name):\n"
            "    module = __import__(module_name)\n"
            "    return getattr(module, function_name)()\n"
        ),
        "src/notes.md": "Operational notes.\n",
        "migrations/001_init.sql": (
            'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);\n'
            'UPDATE users SET name = "x" WHERE id = 1;\n'
        ),
    },
}

BINARY_FILES = {
    "repo_mixed_content": {"data/blob.bin": b"\x00\x01\x02binary\x00\x03\xff\xfe"},
}


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for repo, files in FIXTURES.items():
        for relpath, content in files.items():
            target = ROOT / repo / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            if relpath.endswith(".bin"):
                target.write_bytes(BINARY_FILES.get(repo, {}).get(relpath, content.encode()))
            else:
                target.write_text(content, encoding="utf-8", newline="\n")
    total = sum(len(files) for files in FIXTURES.values())
    print(f"wrote {total} files across {len(FIXTURES)} fixture repositories in {ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
