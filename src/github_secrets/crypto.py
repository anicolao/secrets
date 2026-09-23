"""Explicit identities and SOPS with no ambient hooks. SPDX-License-Identifier: GPL-3.0-only."""
import base64
import contextlib
import struct
import os
import stat
import tempfile
from pathlib import Path
from .common import (Error, MAX_DOCUMENT, MAX_RECORD, child_env, fields, json_bytes,
                     parse_json, read_limited, recipient, recipients, require, run)
from .inputs import hidden
from .model import payload_value


class Identities:
    def __init__(self, config):
        self.config = config
        self._keys = None
        self.public = []

    def load_source(self, source):
        path = Path(source['path']).expanduser().absolute()
        try:
            info = path.lstat()
        except OSError:
            raise Error('Identity file is missing; register a key with identity add.') from None
        require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o077 == 0,
                'Identity must be a regular private file; set its permissions to 0600.')
        raw = read_limited(path, MAX_RECORD)
        if source['type'] == 'ssh-ed25519':
            # The OpenSSH envelope exposes the public algorithm even when encrypted.
            # Reject RSA/ECDSA and unsupported ciphers before asking for a passphrase.
            try:
                lines = raw.decode('ascii').splitlines()
                require(lines[0] == '-----BEGIN OPENSSH PRIVATE KEY-----', 'Expected an OpenSSH Ed25519 key.')
                envelope = base64.b64decode(''.join(lines[1:-1]), validate=True)
                require(envelope.startswith(b'openssh-key-v1\0'), 'Invalid SSH private key format.')
                offset = 15
                def field():
                    nonlocal offset
                    size = struct.unpack('>I', envelope[offset:offset+4])[0]
                    offset += 4
                    result = envelope[offset:offset+size]
                    require(len(result) == size, 'Invalid SSH key envelope.')
                    offset += size
                    return result
                cipher = field()
                field()  # KDF name
                field()  # KDF options
                count = struct.unpack('>I', envelope[offset:offset+4])[0]
                offset += 4
                public = field()
                require(count == 1 and public.startswith(b'\x00\x00\x00\x0bssh-ed25519'),
                        'Only file-backed Ed25519 SSH identities are supported.')
                require(cipher in (b'none', b'aes256-ctr', b'aes256-cbc'), 'Unsupported SSH key encryption cipher.')
            except (ValueError, UnicodeError, IndexError, struct.error):
                raise Error('Invalid OpenSSH Ed25519 identity.') from None
            try:
                raw = run(['ssh-to-age', '-private-key', '-i', str(path)])
            except Error:
                passphrase = hidden('SSH private key passphrase: ')
                raw = run(['ssh-to-age', '-private-key', '-stdinpass', '-i', str(path)],
                          (passphrase + '\n').encode())
            # Conversion must produce native keys, never a direct SSH stanza.
        elif source['type'] != 'age':
            raise Error('Unsupported identity type.', 2)
        try:
            keys = [line.strip() for line in raw.decode('ascii').splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
        except UnicodeError:
            raise Error('Invalid identity file.') from None
        require(keys and all(key.startswith('AGE-SECRET-KEY-1') for key in keys),
                'Only Ed25519-derived or native X25519 identities are supported.')
        pairs = []
        for key in keys:
            pub = run(['age-keygen', '-y'], (key + '\n').encode()).decode().strip()
            pairs.append((recipient(pub), key))
        if source['type'] == 'ssh-ed25519' and path.with_name(path.name + '.pub').exists():
            pub = run(['ssh-to-age'], read_limited(path.with_name(path.name + '.pub'), MAX_RECORD)).decode().strip()
            require(len(pairs) == 1 and pairs[0][0] == pub, 'SSH public file does not match private identity.')
        return pairs

    def load(self):
        if self._keys is None:
            sources = self.config.data['identities'] or [
                {'path': str(Path.home() / '.ssh/id_ed25519'), 'type': 'ssh-ed25519'}]
            self._keys = dict(pair for source in sources for pair in self.load_source(source))
            self.public = sorted(self._keys)
        return self

    def self_recipient(self):
        self.load()
        selected = self.config.data.get('self')
        if selected:
            require(selected in self._keys, 'Selected identity is not available; use identity default.', 2)
            return selected
        require(len(self.public) == 1, 'Multiple identities available; use identity default.', 2)
        return self.public[0]

    @contextlib.contextmanager
    def key_env(self, only=None):
        self.load()
        selected = [only] if only else self.public
        require(all(key in self._keys for key in selected), 'Requested identity is unavailable.')
        # SOPS reopens the key file for each recipient, so it must be seekable.
        # Use a private, short-lived runtime file; never configuration or cache state.
        with tempfile.TemporaryDirectory(prefix='secrets-runtime-') as directory:
            keyfile = Path(directory) / 'keys.txt'
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write('\n'.join(self._keys[key] for key in selected) + '\n')
            env = child_env({'SOPS_AGE_KEY_FILE': str(keyfile), 'XDG_CONFIG_HOME': directory})
            try:
                yield env
            finally:
                keyfile.unlink(missing_ok=True)



class Crypto:
    def __init__(self, identities):
        self.identities = identities

    def validate_ciphertext(self, raw, audience):
        doc = parse_json(raw)
        require(isinstance(doc, dict), 'Invalid SOPS document.')
        fields(doc, ('schema', 'name', 'encoding', 'value', 'lifecycle', 'sops')) if 'lifecycle' in doc else fields(doc, ('schema', 'name', 'encoding', 'value', 'sops'))
        meta = doc['sops']
        require(isinstance(meta, dict), 'Invalid SOPS metadata.')
        allowed = {'age', 'kms', 'gcp_kms', 'azure_kv', 'hc_vault', 'pgp', 'lastmodified',
                   'mac', 'unencrypted_suffix', 'version'}
        require(set(meta) <= allowed, 'Unsupported SOPS metadata or encryption policy.')
        for backend in ('kms', 'gcp_kms', 'azure_kv', 'hc_vault', 'pgp'):
            require(not meta.get(backend), 'Only age recipients are supported.')
        entries = meta.get('age')
        require(isinstance(entries, list), 'Missing SOPS age recipients.')
        require(recipients([item['recipient'] for item in entries]) == recipients(audience),
                'Recipient record and ciphertext do not match.')
        def encrypted(value):
            if isinstance(value, dict):
                for item in value.values():
                    encrypted(item)
            elif isinstance(value, list):
                for item in value:
                    encrypted(item)
            elif value is not None and value != '':
                require(isinstance(value, str) and value.startswith('ENC[AES256_GCM,'),
                        'Unencrypted payload value is forbidden.')
        for key, value in doc.items():
            if key != 'sops':
                encrypted(value)
        return doc

    def decrypt(self, raw, policy, only=None):
        self.validate_ciphertext(raw, policy['recipients'])
        with self.identities.key_env(only) as env:
            result = run(['sops', '--config', '/dev/null', 'decrypt', '--input-type', 'json', '--output-type', 'json', '/dev/stdin'], raw, env)
        payload = parse_json(result)
        payload_value(payload, policy['name'])
        return payload

    def encrypt(self, payload, policy):
        # Fresh encryption generates a new data key on every mutation, including removal.
        raw = run(['sops', '--config', '/dev/null', 'encrypt', '--age', ','.join(policy['recipients']),
                   '--input-type', 'json', '--output-type', 'json', '/dev/stdin'], json_bytes(payload))
        require(len(raw) <= MAX_DOCUMENT, 'Encrypted document exceeds size limit.')
        self.validate_ciphertext(raw, policy['recipients'])
        require(self.decrypt(raw, policy) == payload, 'Encryption round-trip verification failed.')
        return raw
