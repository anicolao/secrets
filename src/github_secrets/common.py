"""Validation and private runtime utilities. SPDX-License-Identifier: GPL-3.0-only."""
import base64
import hashlib
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import os
import re
import selectors
import time
import subprocess
import tempfile
from pathlib import Path

MAX_VALUE = 1024 * 1024
MAX_DOCUMENT = 4 * MAX_VALUE
MAX_RECORD = 64 * 1024
MAX_SECRETS = 1000
MAX_CACHE_BYTES = 128 * MAX_VALUE


class Error(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


def require(condition, message, code=1):
    if not condition:
        raise Error(message, code)


def name(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', value),
            'Invalid secret name.', 2)
    return value


def repo_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', value),
            'Expected a GitHub OWNER/REPO name.', 2)
    require(value.split('/')[1] not in ('.', '..'), 'Invalid repository name.', 2)
    return value


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'Invalid Git object ID.')
    return value


def recipient(value):
    if isinstance(value, str) and value.startswith('ssh-rsa '):
        try:
            key = serialization.load_ssh_public_key(value.encode('ascii'))
            require(isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 16384,
                    'RSA recipients require a 2048–16384 bit key.', 2)
            return key.public_bytes(serialization.Encoding.OpenSSH,
                                    serialization.PublicFormat.OpenSSH).decode('ascii')
        except (ValueError, UnicodeError, UnsupportedAlgorithm):
            raise Error('Invalid SSH RSA recipient.', 2) from None
    # Native age X25519 uses Bech32 with a 32-byte payload and checksum.
    require(isinstance(value, str) and re.fullmatch(r'age1[023456789acdefghjklmnpqrstuvwxyz]{58}', value),
            'Expected a complete age X25519 or SSH RSA recipient.', 2)
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    data = [alphabet.index(c) for c in value[4:]]
    expanded = [ord(c) >> 5 for c in 'age'] + [0] + [ord(c) & 31 for c in 'age']
    chk = 1
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    for item in expanded + data:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ item
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                chk ^= generator
    require(chk == 1 and data[-7] & 15 == 0, 'Invalid age recipient checksum or encoding.', 2)
    return value


def recipients(values):
    require(isinstance(values, list) and 1 <= len(values) <= 100, 'Expected 1–100 recipients.')
    values = [recipient(value) for value in values]
    require(len(set(values)) == len(values), 'Duplicate recipient.')
    return sorted(values)


def discovery_token(value):
    value = recipient(value)
    if value.startswith('ssh-rsa '):
        return 'rsasha256' + hashlib.sha256(base64.b64decode(value.split()[1])).hexdigest()
    return value


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def parse_json(raw, limit=MAX_DOCUMENT):
    require(len(raw) <= limit, 'JSON document exceeds size limit.')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field.')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Error('Invalid JSON constant.')))
    except (ValueError, UnicodeError, RecursionError):
        raise Error('Invalid JSON document.') from None


def fields(obj, expected):
    require(isinstance(obj, dict) and set(obj) == set(expected), 'Unexpected document fields.')


def private_dir(path):
    path = Path(path)
    require(not path.is_symlink(), 'Refusing a symlink for private application state.')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(path.is_dir(), 'Invalid private state directory.')
    os.chmod(path, 0o700)
    return path


def atomic_write(path, raw):
    path = Path(path)
    private_dir(path.parent)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_limited(path, limit):
    try:
        with open(path, 'rb') as stream:
            data = stream.read(limit + 1)
    except OSError:
        raise Error('Cannot read the requested input file.') from None
    require(len(data) <= limit, 'Input exceeds size limit.')
    return data


def child_env(extra=None):
    # Never propagate arbitrary user secret variables, SOPS hooks, or GH debug flags.
    allowed = ('PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'LANG', 'LC_ALL',
               'SSL_CERT_FILE', 'NIX_SSL_CERT_FILE', 'SSL_CERT_DIR')
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    if extra:
        result.update(extra)
    return result


def run(args, data=None, env=None, limit=MAX_DOCUMENT * 3):
    """Bounded pipes; no child output or arguments in errors or temporary files."""
    process = None
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=env or child_env())
        output, offset = bytearray(), 0
        data = data or b''
        deadline = time.monotonic() + 120
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            if data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                require(time.monotonic() < deadline, 'External command timed out.')
                for event, _ in selector.select(timeout=0.5):
                    stream = event.fileobj
                    if stream is process.stdout:
                        chunk = os.read(stream.fileno(), 65536)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            output.extend(chunk)
                            require(len(output) <= limit, 'External command output exceeds size limit.')
                    else:
                        try:
                            offset += os.write(stream.fileno(), data[offset:offset+65536])
                        except BrokenPipeError:
                            offset = len(data)
                        if offset >= len(data):
                            selector.unregister(stream)
                            stream.close()
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        require(process.returncode == 0, 'External command failed; verify tool setup and access.')
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise Error('External command timed out.') from None
    except OSError:
        raise Error('Required command failed; use the Nix flake and verify local setup.') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream and not stream.closed:
                    stream.close()
