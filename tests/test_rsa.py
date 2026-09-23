import contextlib
import copy
import io
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from github_secrets.cli import App, parser
from github_secrets.common import Error, discovery_token, recipient, recipients, run
from github_secrets.crypto import Crypto, Identities
from github_secrets.github import GitHub
from github_secrets.model import policy, validate_policy, new_payload
from support import FakeGitHub, Sandbox


class RSATests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.close)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.path = self.write_key()
        self.source = {'path': str(self.path), 'type': 'ssh-rsa'}
        self.box.config.update(lambda data: data.update(identities=[self.source], self=None))

    def write_key(self, form=serialization.PrivateFormat.OpenSSH, password=None, label='rsa'):
        encoding = serialization.Encoding.PEM
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        path = self.box.root / label
        path.write_bytes(self.key.private_bytes(encoding, form, encryption))
        path.chmod(0o600)
        return path

    def test_private_formats_and_passphrases(self):
        for form in (serialization.PrivateFormat.OpenSSH, serialization.PrivateFormat.TraditionalOpenSSL,
                     serialization.PrivateFormat.PKCS8):
            for password in (None, b'fixture-only'):
                with self.subTest(form=form, encrypted=bool(password)):
                    self.write_key(form, password)
                    with patch('github_secrets.crypto.hidden', return_value='fixture-only') as prompt:
                        ids = Identities(self.box.config).load()
                    self.assertEqual(prompt.call_count, int(password is not None))
                    self.assertEqual(ids.public, [self.public])
                    p = policy('TOKEN', ids.public)
                    crypto = Crypto(ids)
                    payload = new_payload('TOKEN', b'fake')
                    self.assertEqual(crypto.decrypt(crypto.encrypt(payload, p), p), payload)
        with patch('github_secrets.crypto.hidden', return_value='wrong'):
            with self.assertRaises(Error):
                Identities(self.box.config).load()

    def test_canonical_public_and_weak_keys(self):
        self.assertEqual(recipient(self.public + ' user@host'), self.public)
        with self.assertRaises(Error):
            recipients([self.public, self.public + ' other-comment'])
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
        for value in (weak.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(),
                      'ssh-rsa bad-base64', 'ssh-rsa ' + self.public.split()[1][:-4]):
            with self.assertRaises(Error):
                recipient(value)
        pubfile = self.path.with_name(self.path.name + '.pub')
        pubfile.write_text(self.public + ' comment\n')
        Identities(self.box.config).load()
        pubfile.write_text('ssh-rsa invalid')
        with self.assertRaises(Error):
            Identities(self.box.config).load()

    def test_default_rsa_and_ed25519_preference(self):
        ssh = self.box.root / '.ssh'
        ssh.mkdir()
        (ssh / 'id_rsa').write_bytes(self.path.read_bytes())
        (ssh / 'id_rsa').chmod(0o600)
        self.box.config.update(lambda data: data.update(identities=[], self=None))
        with patch('github_secrets.crypto.Path.home', return_value=self.box.root):
            self.assertEqual(Identities(self.box.config).load().public, [self.public])
            ed = ssh / 'id_ed25519'
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(ed)])
            self.assertTrue(Identities(self.box.config).load().public[0].startswith('age1'))
            self.box.config.update(lambda data: data.update(identities=[self.source]))
            self.assertEqual(Identities(self.box.config).load().public, [self.public])
            self.box.config.update(lambda data: data.update(identities=[]))
            ed.write_bytes(b'invalid')
            with self.assertRaises(Error):
                Identities(self.box.config).load()

    def test_mixed_recipients_multiple_sources_and_selection(self):
        native, public = self.box.identity()
        other = self.box.root / 'other'
        run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048', '-N', '', '-f', str(other)])
        other_source = {'path': str(other), 'type': 'ssh-rsa'}
        p = policy('TOKEN', [public, self.public])
        payload = new_payload('TOKEN', b'fake mixed value')
        rsa_crypto = Crypto(Identities(self.box.config))
        raw = rsa_crypto.encrypt(payload, p)
        self.box.use(native)
        self.assertEqual(Crypto(Identities(self.box.config)).decrypt(raw, p), payload)
        self.box.config.update(lambda data: data.update(identities=[other_source, self.source]))
        mixed = Crypto(Identities(self.box.config))
        self.assertEqual(mixed.decrypt(raw, p), payload)
        wrong = Identities(self.box.config).load_source(other_source)[0][0]
        with self.assertRaises(Error):
            mixed.decrypt(raw, p, only=wrong)
        self.assertEqual(mixed.decrypt(raw, p, only=self.public), payload)
        # An ambient RSA private key must not defeat explicit selection, even in stock SOPS.
        ambient = self.box.root / '.ssh'
        ambient.mkdir()
        (ambient / 'id_rsa').write_bytes(self.path.read_bytes())
        self.box.config.update(lambda data: data.update(identities=[other_source]))
        with patch.dict(os.environ, {'HOME': str(self.box.root)}):
            ids = Identities(self.box.config).load()
            with ids.key_env(wrong) as env:
                with self.assertRaises(Error):
                    run(['sops', 'decrypt', '--input-type', 'json', '--output-type', 'json', '/dev/stdin'], raw, env)

    def test_runtime_permissions_and_cleanup_on_error(self):
        ids = Identities(self.box.config).load()
        with self.assertRaises(RuntimeError):
            with ids.key_env(self.public) as env:
                paths = [Path(env[key]) for key in ('SOPS_AGE_KEY_FILE', 'SOPS_AGE_SSH_PRIVATE_KEY_FILE')]
                self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in paths))
                self.assertFalse(any('PRIVATE KEY' in value for value in env.values()))
                raise RuntimeError('fixture')
        self.assertTrue(all(not path.exists() for path in paths))

    def test_policy_tokens_and_search_query(self):
        native, public = self.box.identity()
        self.assertEqual(policy('TOKEN', [public])['version'], 1)
        p = policy('TOKEN', [self.public, public])
        self.assertEqual(p['version'], 2)
        self.assertEqual(validate_policy(p, 'TOKEN'), p)
        token = discovery_token(self.public)
        self.assertEqual(len(token), 73)
        self.assertEqual(discovery_token(self.public + ' comment'), token)
        forged = copy.deepcopy(p)
        forged['search_tokens'][0] = 'forged'
        with self.assertRaises(Error):
            validate_policy(forged, 'TOKEN')
        forged = copy.deepcopy(p)
        forged['version'] = 1
        del forged['search_tokens']
        with self.assertRaises(Error):
            validate_policy(forged, 'TOKEN')
        gh = GitHub()
        with patch.object(gh, 'api', return_value={'items': [], 'total_count': 0}) as api:
            self.assertEqual(gh.search([self.public]), ([], []))
        query = unquote(api.call_args.args[0])
        self.assertIn(token, query)
        self.assertNotIn(self.public, query)
        self.assertLess(len(query), 256)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            App(self.box.config, gh).execute(parser().parse_args(['identity', 'show']))
        self.assertEqual(json.loads(output.getvalue())['search_tokens'][self.public], token)

    def test_rsa_sharing_discovery_and_removal_history(self):
        native, public = self.box.identity()
        self.box.use(native)
        self.box.config.update(lambda data: data.update(default='alice/vault'))
        gh = FakeGitHub()
        app = App(self.box.config, gh)
        value = self.box.root / 'value'
        value.write_bytes(b'fake original value')
        def execute(app, args):
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                code = app.execute(parser().parse_args(args))
            self.assertEqual(code, 0)
            return out.getvalue(), err.getvalue()
        execute(app, ['add', 'TOKEN', '--file', str(value)])
        execute(app, ['recipients', 'add', 'TOKEN', self.public + ' comment'])
        before = app.fetch('alice/vault')
        old_policy, old_payload = app.read_secret(before, 'TOKEN')
        self.assertEqual(old_policy['version'], 2)
        old_raw = before.read('secrets/TOKEN/value.sops.json')
        self.box.config.update(lambda data: data.update(identities=[self.source], self=None))
        rsa_app = App(self.box.config, gh)
        out, _ = execute(rsa_app, ['secrets', 'list', '--json'])
        self.assertEqual([item['name'] for item in json.loads(out)['items']], ['TOKEN'])
        self.box.use(native)
        app = App(self.box.config, gh)
        _, warning = execute(app, ['recipients', 'remove', 'TOKEN', self.public + ' comment'])
        self.assertIn('does not revoke', warning)
        self.assertIn('rotation-needed', warning)
        after = app.fetch('alice/vault')
        new_policy, new_payload_value = app.read_secret(after, 'TOKEN')
        self.assertEqual(new_policy['version'], 1)
        self.assertEqual(new_payload_value['lifecycle']['generation'], old_payload['lifecycle']['generation'])
        self.assertEqual(new_payload_value['lifecycle']['removals'][-1]['recipient'], self.public)
        self.assertEqual(rsa_app.crypto.decrypt(old_raw, old_policy), old_payload)
        with self.assertRaises(Error):
            rsa_app.read_secret(after, 'TOKEN')
