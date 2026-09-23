import contextlib
import copy
import io
import os
import unittest
from unittest.mock import patch
from github_secrets.cli import App, main, parser
from github_secrets.common import Error, child_env, json_bytes, parse_json, recipient, run
from github_secrets.crypto import Crypto, Identities
from github_secrets.inputs import dotenv, read_value
from github_secrets.model import (changed_recipients, lifecycle_status, new_payload, payload_value,
                                  policy, validate_lifecycle)
from support import Sandbox


class InputTests(unittest.TestCase):
    def test_argv_secret_is_not_echoed_and_has_no_side_effects(self):
        for args in (['add', 'TOKEN', 'VERY_PRIVATE_VALUE'], ['add', 'TOKEN', '--value', 'VERY_PRIVATE_VALUE'],
                     ['add', 'TOKEN', '--stdin', '--file', 'VERY_PRIVATE_VALUE']):
            with patch('github_secrets.cli.App') as app, contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(main(args), 2)
                app.assert_not_called()
                self.assertNotIn('VERY_PRIVATE_VALUE', error.getvalue())

    def test_env_empty_unset_and_child_scrubbing(self):
        args = parser().parse_args(['add', 'TOKEN', '--from-env', 'SAMPLE_TOKEN'])
        with patch.dict(os.environ, {'SAMPLE_TOKEN': '', 'UNRELATED_SECRET': 'private', 'SOPS_AGE_KEY_CMD': 'bad'}):
            self.assertEqual(read_value(args), b'')
            self.assertNotIn('UNRELATED_SECRET', child_env())
            self.assertNotIn('SOPS_AGE_KEY_CMD', child_env())
            with self.assertRaises(Error):
                read_value(args)

    def test_dotenv_does_not_execute_or_expand(self):
        values = dotenv(b'# comment\nexport TOKEN="a\\nb"\nEMPTY=\nLITERAL=\'$(touch /nope) $HOME\'\n')
        self.assertEqual(values, {'TOKEN': b'a\nb', 'EMPTY': b'', 'LITERAL': b'$(touch /nope) $HOME'})

    def test_dotenv_comment_rules(self):
        self.assertEqual(dotenv(b'A= # comment\nB=#literal\nC=x # comment'),
                         {'A': b'', 'B': b'#literal', 'C': b'x'})

    def test_dotenv_invalid_and_duplicates_redacted(self):
        for raw in (b'A=private\nA=private', b'A="private', b'bad private', b'A=x\na=y'):
            with self.assertRaises(Error) as caught:
                dotenv(raw)
            self.assertNotIn('private', str(caught.exception))

    def test_external_output_is_bounded_and_redacted(self):
        import sys
        with self.assertRaises(Error) as error:
            run([sys.executable, '-c', 'print("x" * 100000)'], limit=100)
        self.assertNotIn('xxxxx', str(error.exception))

    def test_json_duplicate_fields(self):
        with self.assertRaises(Error):
            parse_json(b'{"x":1,"x":2}')


class RealCryptoTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.close)
        self.alice, self.apub = self.box.identity()
        self.bob, self.bpub = self.box.identity('bob')
        self.box.use(self.alice)
        self.ids = Identities(self.box.config)
        self.crypto = Crypto(self.ids)

    def test_native_recipient_checksum(self):
        self.assertEqual(recipient(self.apub), self.apub)
        with self.assertRaises(Error):
            recipient(self.apub[:-1] + ('q' if self.apub[-1] != 'q' else 'p'))

    def test_roundtrip_bytes_and_stock_sops(self):
        for value in (b'', b'line\nline\n', b'\x00\xff\x01', b'x' * 1048576):
            with self.subTest(size=len(value)):
                p = policy('TOKEN', [self.apub])
                payload = new_payload('TOKEN', value)
                raw = self.crypto.encrypt(payload, p)
                self.assertEqual(self.crypto.decrypt(raw, p), payload)
                with self.ids.key_env() as env:
                    plain = run(['sops', 'decrypt', '--input-type', 'json', '--output-type', 'json', '/dev/stdin'], raw, env)
                self.assertEqual(payload_value(parse_json(plain), 'TOKEN'), value)

    def test_nonrecipient_and_policy_mismatch(self):
        p = policy('TOKEN', [self.apub])
        raw = self.crypto.encrypt(new_payload('TOKEN', b'fake'), p)
        with self.assertRaises(Error):
            self.crypto.decrypt(raw, policy('TOKEN', [self.bpub]))
        self.box.use(self.bob)
        with self.assertRaises(Error):
            Crypto(Identities(self.box.config)).decrypt(raw, p)

    def test_corruption_and_unencrypted_values_rejected(self):
        p = policy('TOKEN', [self.apub])
        raw = self.crypto.encrypt(new_payload('TOKEN', b'fake'), p)
        obj = parse_json(raw)
        obj['value'] = 'plaintext'
        with self.assertRaises(Error):
            self.crypto.decrypt(json_bytes(obj), p)
        obj = parse_json(raw)
        obj['sops']['mac'] = obj['sops']['mac'].replace('data:', 'data:AAAA', 1)
        with self.assertRaises(Error):
            self.crypto.decrypt(json_bytes(obj), p)
        obj = parse_json(raw)
        obj['sops']['key_groups'] = []
        with self.assertRaises(Error):
            self.crypto.decrypt(json_bytes(obj), p)

    def test_ssh_identity_and_stale_public_file(self):
        path = self.box.root / 'sshkey'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)])
        ids = Identities(self.box.config)
        pairs = ids.load_source({'path': str(path), 'type': 'ssh-ed25519'})
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs, ids.load_source({'path': str(path), 'type': 'ssh-ed25519'}))
        other = self.box.root / 'other'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)])
        path.with_suffix('.pub').write_bytes(other.with_suffix('.pub').read_bytes())
        with self.assertRaises(Error):
            ids.load_source({'path': str(path), 'type': 'ssh-ed25519'})

    def test_encrypted_ssh_identity(self):
        path = self.box.root / 'locked'
        # This is a throwaway test passphrase, never a user's credential.
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', 'fixture-only', '-f', str(path)])
        with patch('github_secrets.crypto.hidden', return_value='fixture-only'):
            pairs = self.ids.load_source({'path': str(path), 'type': 'ssh-ed25519'})
        self.assertEqual(len(pairs), 1)

    def test_default_ssh_source_without_registration(self):
        ssh = self.box.root / '.ssh'
        ssh.mkdir()
        path = ssh / 'id_ed25519'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)])
        self.box.config.update(lambda data: data.update(identities=[], self=None))
        with patch('github_secrets.crypto.Path.home', return_value=self.box.root):
            ids = Identities(self.box.config).load()
            self.assertEqual(ids.self_recipient(), ids.public[0])

    def test_unsupported_ssh_type_never_prompts(self):
        path = self.box.root / 'rsa'
        run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048', '-N', '', '-f', str(path)])
        with patch('github_secrets.crypto.hidden') as prompt:
            with self.assertRaises(Error):
                self.ids.load_source({'path': str(path), 'type': 'ssh-ed25519'})
            prompt.assert_not_called()

    def test_private_key_permissions(self):
        self.alice.chmod(0o644)
        with self.assertRaises(Error):
            self.ids.load()

    def test_runtime_key_is_removed(self):
        with self.ids.key_env() as env:
            keypath = env['SOPS_AGE_KEY_FILE']
            self.assertTrue(os.path.exists(keypath))
        self.assertFalse(os.path.exists(keypath))


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.close)
        _, self.recipient = self.box.identity()
        self.payload = new_payload('TOKEN', b'old', generated_at='2026-09-23T09:00:00Z', time='2026-09-23T09:01:00Z')
        self.removed = changed_recipients(self.payload, self.recipient, time='2026-09-23T10:00:00Z')

    def status(self, payload):
        return lifecycle_status(payload.get('lifecycle'))['removal_status']

    def test_removal_preserves_generation_and_value(self):
        self.assertEqual(self.status(self.payload), 'no-removals-recorded')
        self.assertEqual(self.status(self.removed), 'rotation-needed')
        self.assertEqual(self.payload['lifecycle']['generation'], self.removed['lifecycle']['generation'])
        self.assertEqual(self.payload['value'], self.removed['value'])
        self.assertEqual(self.status(changed_recipients(self.removed)), 'rotation-needed')

    def test_identical_replacement_cannot_clear_warning(self):
        self.assertIsNone(new_payload('TOKEN', b'old', self.removed))
        with self.assertRaises(Error):
            new_payload('TOKEN', b'old', self.removed, '2026-09-23T11:00:00Z')

    def test_generation_vs_recording(self):
        self.assertEqual(self.status(new_payload('TOKEN', b'new', self.removed, time='2026-09-23T11:00:00Z')), 'unknown')
        for generated, expected in [('2026-09-23T09:30:00Z', 'rotation-needed'),
                                     ('2026-09-23T10:00:00Z', 'rotation-needed'),
                                     ('2026-09-23T10:30:00Z', 'replacement-recorded')]:
            new = new_payload('TOKEN', b'new', self.removed, generated, '2026-09-23T11:00:00Z')
            self.assertEqual(self.status(new), expected)
            later = changed_recipients(new, self.recipient, '2026-09-23T12:00:00Z')
            self.assertEqual(self.status(later), 'rotation-needed')
            self.assertEqual(len(later['lifecycle']['removals']), 2)

    def test_bad_or_missing_history_is_unknown_and_blocks_writes(self):
        payload = copy.deepcopy(self.removed)
        del payload['lifecycle']
        self.assertEqual(self.status(payload), 'unknown')
        with self.assertRaises(Error):
            new_payload('TOKEN', b'new', payload)
        with self.assertRaises(Error):
            new_payload('TOKEN', b'new', generated_at='2027-01-01T00:00:00Z', time='2026-01-01T00:00:00Z')
