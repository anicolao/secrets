import base64
import copy
import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from github_secrets.common import Error, json_bytes, run
from github_secrets.config import Config
from github_secrets.model import MARKER


class Sandbox:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='secrets-test-')
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.root / 'config'),
                                           'XDG_CACHE_HOME': str(self.root / 'cache'),
                                           'XDG_STATE_HOME': str(self.root / 'state')})
        self.env.start()
        self.config = Config()

    def close(self):
        self.env.stop()
        self.temp.cleanup()

    def identity(self, label='alice'):
        path = self.root / (label + '.txt')
        path.write_bytes(run(['age-keygen']))
        path.chmod(0o600)
        public = run(['age-keygen', '-y', str(path)]).decode().strip()
        return path, public

    def use(self, path):
        self.config.update(lambda data: data.update(identities=[{'path': str(path), 'type': 'age'}], self=None))


class FakeGitHub:
    """Git object/ref semantics with immutable snapshots and rejected divergent pushes."""
    def __init__(self):
        self.repository = {'id': 123, 'full_name': 'alice/vault', 'default_branch': 'main'}
        self.blobs, self.trees, self.commits = {}, {}, {}
        self.counter = 0
        self.fail = None
        self.search_errors = []
        self.create('alice/vault')
        self.put({'vault.json': json_bytes(MARKER)})

    def object_id(self, value):
        return hashlib.sha1(json_bytes(value)).hexdigest()

    def blob(self, raw):
        key = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        self.blobs[key] = raw
        return key

    def create(self, repo, public=False):
        tree = self.object_id({})
        self.trees[tree] = {}
        self.current = self.commit(tree, [])
        return self.repository

    def commit(self, tree, parents):
        self.counter += 1
        key = hashlib.sha1(f'{tree}:{parents}:{self.counter}'.encode()).hexdigest()
        self.commits[key] = {'sha': key, 'commit': {'tree': {'sha': tree}}, 'parents': parents}
        return key

    def put(self, changes):
        files = dict(self.trees[self.commits[self.current]['commit']['tree']['sha']])
        for path, raw in changes.items():
            files[path] = {'sha': self.blob(raw), 'size': len(raw), 'mode': '100644', 'type': 'blob', 'path': path}
        tree = self.object_id(files)
        self.trees[tree] = files
        self.current = self.commit(tree, [self.current])

    def info(self, repo):
        return copy.deepcopy(self.repository)

    def head(self, info):
        return copy.deepcopy(self.commits[self.current])

    def search(self, public):
        return ['alice/vault'], self.search_errors

    def api(self, endpoint, method='GET', body=None):
        if '/git/trees/' in endpoint and method == 'GET':
            tree = endpoint.split('/git/trees/')[1].split('?')[0]
            return {'tree': copy.deepcopy(list(self.trees[tree].values())), 'truncated': False}
        if '/git/blobs/' in endpoint:
            raw = self.blobs[endpoint.rsplit('/', 1)[1]]
            return {'encoding': 'base64', 'content': base64.b64encode(raw).decode()}
        if endpoint.endswith('/git/blobs'):
            return {'sha': self.blob(base64.b64decode(body['content']))}
        if endpoint.endswith('/git/trees'):
            tree = copy.deepcopy(self.trees[body['base_tree']])
            for entry in body['tree']:
                tree[entry['path']] = {**entry, 'size': len(self.blobs[entry['sha']])}
            key = self.object_id(tree)
            self.trees[key] = tree
            return {'sha': key}
        if endpoint.endswith('/git/commits'):
            return {'sha': self.commit(body['tree'], body['parents'])}
        if '/git/refs/heads/' in endpoint:
            if self.fail == 'conflict':
                self.put({'README.md': b'Concurrent edit'})
            if self.fail == 'before-update':
                raise Error('Injected failure')
            assert body['force'] is False
            if self.commits[body['sha']]['parents'] != [self.current]:
                raise Error('Non-fast-forward')
            self.current = body['sha']
            if self.fail == 'lost-response':
                raise Error('Injected lost response')
            return {'object': {'sha': self.current}}
        if '/compare/' in endpoint:
            return {'status': 'diverged'}
        raise AssertionError((endpoint, method))
