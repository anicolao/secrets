"""GitHub transport, immutable snapshots, atomic Git publication.

SPDX-License-Identifier: GPL-3.0-only
"""
import base64
import hashlib
import os
import re
import time
from pathlib import Path
from urllib.parse import quote
from .common import (Error, MAX_CACHE_BYTES, MAX_DOCUMENT, MAX_RECORD, MAX_SECRETS,
                     atomic_write, child_env, discovery_token, json_bytes, name, parse_json, private_dir,
                     read_limited, repo_name, require, run, sha)
from .model import MARKER, now


class GitHub:
    def __init__(self):
        self.limited_until = {}

    def env(self):
        names = ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_CONFIG_DIR', 'XDG_CONFIG_HOME')
        return child_env({key: os.environ[key] for key in names if key in os.environ})

    def api(self, endpoint, method='GET', body=None):
        resource = 'search' if endpoint.startswith('search/') else 'core'
        require(time.time() >= self.limited_until.get(resource, 0),
                'GitHub rate limit reached; retry after the server reset time.')
        args = ['gh', 'api', '--hostname', 'github.com', '--include', '--method', method,
                '-H', 'Accept: application/vnd.github+json', endpoint]
        if body is not None:
            args.extend(['--input', '-'])
        try:
            raw = run(args, json_bytes(body) if body is not None else None,
                      self.env(), limit=32 * MAX_DOCUMENT)
        except Error:
            raise Error('GitHub request failed (authentication, permissions, rate limit, or network); results may be partial.') from None
        # gh --include uses LF or CRLF depending on version.
        raw = raw.replace(b'\r\n', b'\n')
        headers, separator, content = raw.partition(b'\n\n')
        require(separator, 'Invalid GitHub response.')
        normalized = {}
        for line in headers.splitlines()[1:]:
            key, sep, value = line.partition(b':')
            if sep:
                normalized[key.lower()] = value.strip()
        try:
            if normalized.get(b'x-ratelimit-remaining') == b'0':
                self.limited_until[resource] = int(normalized[b'x-ratelimit-reset'])
            if b'retry-after' in normalized:
                self.limited_until[resource] = time.time() + int(normalized[b'retry-after'])
        except (ValueError, KeyError):
            pass
        if headers.startswith(b'HTTP/') and b' 204 ' in headers.splitlines()[0]:
            return {}
        return parse_json(content, 32 * MAX_DOCUMENT)

    def info(self, repo):
        result = self.api('repos/' + repo_name(repo))
        require(type(result.get('id')) is int and result['id'] > 0, 'Invalid GitHub repository ID.')
        repo_name(result['full_name'])
        branch = result.get('default_branch')
        require(isinstance(branch, str) and branch and len(branch) <= 255, 'Repository has no default branch.')
        return result

    def head(self, info):
        commit = self.api('repos/' + info['full_name'] + '/commits/' + quote(info['default_branch'], safe=''))
        sha(commit['sha'])
        sha(commit['commit']['tree']['sha'])
        return commit

    def search(self, public):
        found, problems = {}, []
        for key in public:
            for page in range(1, 11):
                query = quote(discovery_token(key) + ' in:file filename:recipients.json', safe='')
                try:
                    result = self.api(f'search/code?q={query}&per_page=100&page={page}')
                    if result.get('incomplete_results') or result.get('total_count', 0) > 1000:
                        problems.append('GitHub search reported incomplete or capped results.')
                    for item in result['items']:
                        path = item.get('path', '')
                        if re.fullmatch(r'secrets/[A-Za-z][A-Za-z0-9_-]{0,63}/recipients.json', path):
                            repo = item['repository']
                            found[repo['id']] = repo_name(repo['full_name'])
                    if len(result['items']) < 100 or page * 100 >= result['total_count']:
                        break
                except (Error, KeyError, TypeError):
                    problems.append('GitHub discovery failed or was rate-limited; known vaults are still checked.')
                    break
        return list(found.values()), problems

    def create(self, repo, public=False):
        repo_name(repo)
        # gh initializes the repository before the Git database API can add the vault marker.
        run(['gh', 'repo', 'create', repo, '--public' if public else '--private', '--add-readme',
             '--description', 'SOPS encrypted secrets with per-secret age recipients'], env=self.env())
        return self.info(repo)


class Snapshot:
    def __init__(self, github, config, info, commit, tree, checked_at, offline=False):
        self.github, self.config, self.info = github, config, info
        self.commit, self.tree, self.checked_at, self.offline = commit, tree, checked_at, offline
        self.files = {}
        self.names = []
        self.validate_tree()

    @property
    def revision(self):
        return self.commit['sha']

    @property
    def prefix(self):
        return 'repos/' + self.info['full_name']

    @property
    def directory(self):
        return private_dir(self.config.cache / str(self.info['id']))

    @classmethod
    def fetch(cls, github, config, repo, offline=False, allow_empty=False):
        repo_name(repo)
        if offline:
            known = next((item for item in config.data['vaults'].values()
                          if item['name'].lower() == repo.lower()), None)
            require(known is not None, 'Vault is not registered for offline use.')
            path = config.cache / str(known['id']) / 'snapshot.json'
            obj = parse_json(read_limited(path, 16 * MAX_DOCUMENT), 16 * MAX_DOCUMENT)
            result = cls(github, config, obj['info'], obj['commit'], obj['tree'], obj['checked_at'], True)
        else:
            info = github.info(repo)
            commit = github.head(info)
            tree = github.api('repos/' + info['full_name'] + '/git/trees/' + commit['commit']['tree']['sha'] + '?recursive=1')
            require(not tree.get('truncated'), 'Repository tree is truncated; refusing an incomplete vault.')
            result = cls(github, config, {'id': info['id'], 'full_name': info['full_name'],
                                          'default_branch': info['default_branch']}, commit, tree, now())
        if not allow_empty:
            marker = parse_json(result.read('vault.json'), MAX_RECORD)
            require(marker == MARKER and type(marker.get('version')) is int, 'Missing or unsupported vault format marker.')
        if not offline:
            result.save()
        return result

    def validate_tree(self):
        repo_name(self.info['full_name'])
        require(type(self.info['id']) is int and self.info['id'] > 0, 'Invalid cached repository ID.')
        sha(self.revision)
        sha(self.commit['commit']['tree']['sha'])
        require(isinstance(self.tree.get('tree'), list) and len(self.tree['tree']) <= 10000,
                'Repository tree exceeds the MVP limit.')
        total = 0
        for item in self.tree['tree']:
            path = item.get('path', '')
            if path in ('vault.json', 'secrets') or path.startswith('secrets/'):
                require(item.get('mode') in ('040000', '100644') and item.get('type') in ('tree', 'blob'),
                        'Symlinks, executable files, and submodules are forbidden in vault paths.')
                if item['type'] == 'tree':
                    require(item['mode'] == '040000', 'Invalid directory mode.')
                    if path != 'secrets':
                        require(re.fullmatch(r'secrets/[A-Za-z][A-Za-z0-9_-]{0,63}', path), 'Unexpected vault directory.')
                    continue
                require(item['mode'] == '100644', 'Invalid secret file mode.')
                match = re.fullmatch(r'secrets/([A-Za-z][A-Za-z0-9_-]{0,63})/(recipients.json|value.sops.json)', path)
                require(path == 'vault.json' or match is not None, 'Unexpected file in a secret directory.')
                require(path not in self.files, 'Duplicate tree path.')
                sha(item['sha'])
                size = item.get('size')
                limit = MAX_DOCUMENT if path.endswith('value.sops.json') else MAX_RECORD
                require(type(size) is int and 0 <= size <= limit, 'Vault file exceeds size limit.')
                total += size
                self.files[path] = item
        require(total <= MAX_CACHE_BYTES, 'Vault exceeds the 128 MiB snapshot limit.')
        self.names = sorted({path.split('/')[1] for path in self.files if path.startswith('secrets/')})
        require(len(self.names) <= MAX_SECRETS and len({n.casefold() for n in self.names}) == len(self.names),
                'Too many secrets or case-colliding names.')
        # Missing pairs are reported per secret during reads, preserving other listing results.

    def save(self):
        atomic_write(self.directory / 'snapshot.json', json_bytes({'info': self.info, 'commit': self.commit,
                      'tree': self.tree, 'checked_at': self.checked_at}))

    def read(self, path):
        require(path in self.files, 'Vault file is missing.')
        item = self.files[path]
        cache = self.directory / 'blobs' / item['sha']
        if cache.exists():
            require(not cache.is_symlink(), 'Invalid cached blob path.')
            raw = read_limited(cache, MAX_DOCUMENT)
        else:
            require(not self.offline, 'Ciphertext is not cached; refresh this vault online first.')
            blob = self.github.api(self.prefix + '/git/blobs/' + item['sha'])
            require(blob.get('encoding') == 'base64', 'Unexpected Git blob encoding.')
            try:
                raw = base64.b64decode(''.join(blob['content'].split()), validate=True)
            except (ValueError, KeyError):
                raise Error('Invalid Git blob.') from None
        require(len(raw) == item['size'], 'Git blob size mismatch.')
        digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(digest == item['sha'], 'Git blob integrity mismatch.')
        if not cache.exists():
            atomic_write(cache, raw)
        return raw

    def publish(self, changes):
        """Write immutable objects, then a non-force ref update. Never leave a partial tree."""
        projected = sum(item['size'] for path, item in self.files.items() if path not in changes)
        for path, raw in changes.items():
            limit = MAX_DOCUMENT if path.endswith('/value.sops.json') else MAX_RECORD
            require(len(raw) <= limit, 'Publication file exceeds its size limit.')
            if path == 'vault.json' or path.startswith('secrets/'):
                projected += len(raw)
        require(projected <= MAX_CACHE_BYTES, 'Publication would exceed the 128 MiB vault limit.')
        pending = self.config.state / (str(self.info['id']) + '.pending.json')
        require(not pending.exists(), 'Unresolved publication exists; inspect pending state before retrying.')
        record = {'version': 1, 'repository': self.info, 'base': self.revision, 'commit': None,
                  'changes': {path: base64.b64encode(raw).decode() for path, raw in changes.items()}}
        atomic_write(pending, json_bytes(record))
        try:
            entries = []
            for path, raw in changes.items():
                require(path in ('vault.json', 'README.md') or re.fullmatch(
                    r'secrets/[A-Za-z][A-Za-z0-9_-]{0,63}/(recipients.json|value.sops.json)', path), 'Unsafe publication path.')
                blob = self.github.api(self.prefix + '/git/blobs', 'POST',
                                       {'content': base64.b64encode(raw).decode(), 'encoding': 'base64'})
                entries.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': sha(blob['sha'])})
            tree = self.github.api(self.prefix + '/git/trees', 'POST',
                                   {'base_tree': self.commit['commit']['tree']['sha'], 'tree': entries})
            commit = self.github.api(self.prefix + '/git/commits', 'POST',
                                     {'message': 'Update encrypted vault contents', 'tree': sha(tree['sha']),
                                      'parents': [self.revision]})
            record['commit'] = sha(commit['sha'])
            atomic_write(pending, json_bytes(record))
            response = self.github.api(self.prefix + '/git/refs/heads/' + quote(self.info['default_branch'], safe=''),
                            'PATCH', {'sha': record['commit'], 'force': False})
            require(response.get('object', {}).get('sha') == record['commit'], 'Unexpected published reference.')
        except Error:
            # A request may have reached GitHub even when its response was lost.
            if record['commit']:
                try:
                    current = self.github.head(self.info)['sha']
                    if current == record['commit'] or self.github.api(
                        self.prefix + '/compare/' + record['commit'] + '...' + current).get('status') == 'ahead':
                        pending.unlink()
                        return record['commit']
                except Error:
                    pass
            raise Error(f'Publication failed or is uncertain. Encrypted pending work: {pending}. '
                        'Inspect the remote revision and follow the recovery instructions; no retry was applied.') from None
        pending.unlink()
        return record['commit']
