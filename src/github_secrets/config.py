"""Private local state. SPDX-License-Identifier: GPL-3.0-only."""
import contextlib
import fcntl
import os
from pathlib import Path
from .common import MAX_RECORD, Error, atomic_write, json_bytes, parse_json, private_dir, read_limited, require


class Config:
    def __init__(self):
        home = Path.home()
        self.directory = private_dir(Path(os.environ.get('XDG_CONFIG_HOME', home / '.config')) / 'secrets')
        self.cache = private_dir(Path(os.environ.get('XDG_CACHE_HOME', home / '.cache')) / 'secrets')
        self.state = private_dir(Path(os.environ.get('XDG_STATE_HOME', home / '.local/state')) / 'secrets')
        self.path = self.directory / 'config.json'
        self.data = self.read()

    def read(self):
        if not self.path.exists():
            return {'version': 1, 'identities': [], 'self': None, 'default': None, 'vaults': {}}
        require(not self.path.is_symlink(), 'Invalid config path.')
        obj = parse_json(read_limited(self.path, MAX_RECORD), MAX_RECORD)
        require(isinstance(obj, dict) and obj.get('version') == 1 and isinstance(obj.get('vaults'), dict)
                and isinstance(obj.get('identities'), list), 'Invalid application configuration.', 2)
        return obj

    @contextlib.contextmanager
    def lock(self, key):
        # Caller uses validated numeric repository IDs or the constant "config".
        path = self.state / (str(key) + '.lock')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error('Another operation is using this local state.') from None
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def update(self, change):
        with self.lock('config'):
            self.data = self.read()
            change(self.data)
            raw = json_bytes(self.data)
            require(len(raw) <= MAX_RECORD, 'Configuration exceeds size limit.')
            atomic_write(self.path, raw)

    def register(self, info, choose_default=False):
        def change(data):
            data['vaults'][str(info['id'])] = {'id': info['id'], 'name': info['full_name']}
            if choose_default and not data['default']:
                data['default'] = info['full_name']
        self.update(change)
