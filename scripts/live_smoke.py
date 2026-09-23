#!/usr/bin/env python3
"""Opt-in live test: fake values in a temporary branch; always remove the branch.

Run: nix develop --command env PYTHONPATH=src python scripts/live_smoke.py OWNER/REPO
Requires GitHub write access. Never uses the user's encryption identity or app state.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import quote
from unittest.mock import patch
from github_secrets.cli import App, parser
from github_secrets.common import Error, json_bytes, recipient, repo_name, run
from github_secrets.config import Config
from github_secrets.github import GitHub, Snapshot
from github_secrets.model import MARKER, payload_value

repo = repo_name(sys.argv[1])
gh = GitHub()
info = gh.info(repo)
base = gh.head(info)['sha']
branch = 'test/mvp-smoke-' + uuid.uuid4().hex[:12]
original_env = gh.env()


class BranchGitHub(GitHub):
    def env(self):
        return original_env

    def info(self, name):
        result = super().info(name)
        result['default_branch'] = branch
        return result


transport = BranchGitHub()
gh.api('repos/' + repo + '/git/refs', 'POST', {'ref': 'refs/heads/' + branch, 'sha': base})
try:
    with tempfile.TemporaryDirectory(prefix='secrets-live-') as directory:
        root = Path(directory)
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(root / 'config'),
                                      'XDG_CACHE_HOME': str(root / 'cache'),
                                      'XDG_STATE_HOME': str(root / 'state')}):
            config = Config()
            keys = []
            for who in ('alice', 'bob'):
                path = root / (who + '.key')
                if who == 'alice':
                    path.write_bytes(run(['age-keygen']))
                    path.chmod(0o600)
                    public = run(['age-keygen', '-y', str(path)]).decode().strip()
                else:
                    run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048', '-N', '', '-f', str(path)])
                    public = recipient(path.with_name(path.name + '.pub').read_text().strip())
                keys.append((path, public))
            def use(index):
                config.update(lambda data: data.update(identities=[{'path': str(keys[index][0]), 'type': 'age' if index == 0 else 'ssh-rsa'}],
                                                       self=None, default=repo))
                return App(config, transport)
            def execute(app, args):
                with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                    code = app.execute(parser().parse_args(args))
                assert code == 0, err.getvalue()
                return out.getvalue(), err.getvalue()
            snapshot = Snapshot.fetch(transport, config, repo, allow_empty=True)
            snapshot.publish({'vault.json': json_bytes(MARKER)})
            alice = use(0)
            value = root / 'fixture'
            value.write_bytes(b'fake-live-value\x00\xff\n')
            execute(alice, ['add', 'TOKEN', '--file', str(value), '--recipient', keys[1][1]])
            before = alice.fetch(repo)
            policy, plaintext = alice.read_secret(before, 'TOKEN')
            old_raw = before.read('secrets/TOKEN/value.sops.json')
            assert payload_value(plaintext, 'TOKEN') == value.read_bytes()
            bob = use(1)
            output, _ = execute(bob, ['secrets', 'list', '--vault', repo, '--json'])
            assert len(json.loads(output)['items']) == 1
            alice = use(0)
            _, warning = execute(alice, ['recipients', 'remove', 'TOKEN', keys[1][1]])
            assert 'does not revoke' in warning and 'rotation-needed' in warning
            after = alice.fetch(repo)
            bob = use(1)
            try:
                bob.read_secret(after, 'TOKEN')
            except Error:
                pass
            else:
                raise AssertionError('Removed key decrypted new revision')
            assert bob.crypto.decrypt(old_raw, policy) == plaintext
            # Verify the actual search endpoint accepts our query. This branch is deliberately
            # not the default branch, so indexing/discoverability is not asserted here.
            found, errors = transport.search([keys[1][1]])
            assert not errors, errors
            print('Live GitHub mixed age/RSA commit/read/list/removal/history/fingerprint-query checks passed.')
finally:
    gh.api('repos/' + repo + '/git/refs/heads/' + quote(branch, safe=''), 'DELETE')
