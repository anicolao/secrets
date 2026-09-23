import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch
from github_secrets.cli import App, parser
from github_secrets.common import run, Error, json_bytes
from github_secrets.github import GitHub, Snapshot
from github_secrets.model import lifecycle_status
from support import FakeGitHub, Sandbox


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.box = Sandbox()
        self.addCleanup(self.box.close)
        self.alice, self.apub = self.box.identity()
        self.bob, self.bpub = self.box.identity('bob')
        self.carol, self.cpub = self.box.identity('carol')
        self.box.use(self.alice)
        self.box.config.update(lambda data: data.update(default='alice/vault'))
        self.gh = FakeGitHub()
        self.app = App(self.box.config, self.gh)

    def execute(self, argv):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            result = self.app.execute(parser().parse_args(argv))
        return result, out.getvalue(), err.getvalue()

    def add(self, secret, value=b'fixture', recipients=(), replace=False):
        path = self.box.root / 'input'
        path.write_bytes(value)
        args = ['add', secret, '--file', str(path)] + (['--replace'] if replace else [])
        for recipient in recipients:
            args += ['--recipient', recipient]
        return self.execute(args)

    def test_mixed_audiences_discovery_and_write(self):
        self.add('PERSONAL')
        self.add('BOB', recipients=[self.bpub])
        self.add('CAROL', recipients=[self.cpub])
        old = Snapshot.fetch(self.gh, self.box.config, 'alice/vault')
        untouched = old.read('secrets/CAROL/value.sops.json')
        self.box.use(self.bob)
        self.app = App(self.box.config, self.gh)
        code, out, _ = self.execute(['secrets', 'list', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual([row['name'] for row in json.loads(out)['items']], ['BOB'])
        self.add('BOB', b'bob replacement', replace=True)
        new = Snapshot.fetch(self.gh, self.box.config, 'alice/vault')
        self.assertEqual(new.read('secrets/CAROL/value.sops.json'), untouched)

    def test_removal_rotates_only_target_and_warns(self):
        self.add('TOKEN', recipients=[self.bpub])
        self.add('OTHER', recipients=[self.bpub])
        before = self.app.fetch('alice/vault')
        old_policy, old_value = self.app.read_secret(before, 'TOKEN')
        old_raw = before.read('secrets/TOKEN/value.sops.json')
        old_other = before.read('secrets/OTHER/value.sops.json')
        code, out, err = self.execute(['recipients', 'remove', 'TOKEN', self.bpub])
        self.assertEqual(code, 0)
        self.assertIn('does not revoke', err)
        self.assertIn('rotation-needed', err)
        after = self.app.fetch('alice/vault')
        _, new_value = self.app.read_secret(after, 'TOKEN')
        self.assertEqual(new_value['value'], old_value['value'])
        self.assertEqual(new_value['lifecycle']['generation'], old_value['lifecycle']['generation'])
        self.assertEqual(after.read('secrets/OTHER/value.sops.json'), old_other)
        self.box.use(self.bob)
        self.app = App(self.box.config, self.gh)
        with self.assertRaises(Error):
            self.app.read_secret(after, 'TOKEN')
        self.assertEqual(self.app.crypto.decrypt(old_raw, old_policy), old_value)

    def test_get_exact_bytes_and_no_output_on_corruption(self):
        import sys
        value = b'fixture\x00\xff\n'
        self.add('TOKEN', value)
        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()
        output = Output()
        with patch.object(sys, 'stdout', output):
            self.app.execute(parser().parse_args(['get', 'TOKEN']))
        self.assertEqual(output.buffer.getvalue(), value)
        snap = self.app.fetch('alice/vault')
        doc = json.loads(snap.read('secrets/TOKEN/value.sops.json'))
        doc['sops']['mac'] = doc['sops']['mac'].replace('data:', 'data:AAAA', 1)
        self.gh.put({'secrets/TOKEN/value.sops.json': json_bytes(doc)})
        output = Output()
        with patch.object(sys, 'stdout', output), self.assertRaises(Error):
            self.app.execute(parser().parse_args(['get', 'TOKEN']))
        self.assertEqual(output.buffer.getvalue(), b'')

    def test_batch_encryption_failure_publishes_nothing(self):
        path = self.box.root / 'batch.env'
        path.write_text('FIRST=one\nSECOND=two\n')
        before = self.gh.current
        encrypt = self.app.crypto.encrypt
        def fail_second(payload, audience):
            if payload['name'] == 'SECOND':
                raise Error('Injected encryption failure')
            return encrypt(payload, audience)
        with patch.object(self.app.crypto, 'encrypt', side_effect=fail_second), self.assertRaises(Error):
            self.execute(['import-env', str(path)])
        self.assertEqual(before, self.gh.current)
        self.assertFalse((self.box.config.state / '123.pending.json').exists())

    def test_create_without_identity_sets_first_default(self):
        self.box.config.update(lambda data: data.update(identities=[], self=None, default=None))
        code, out, _ = self.execute(['create', 'vault', '--owner', 'alice'])
        self.assertEqual(code, 0)
        self.assertEqual(self.box.config.data['default'], 'alice/vault')
        self.assertEqual(self.app.fetch('alice/vault').names, [])

    def test_selected_identity_can_remove_other_local_identity(self):
        self.add('TOKEN', recipients=[self.bpub])
        self.box.config.update(lambda data: data.update(identities=[
            {'path': str(self.alice), 'type': 'age'}, {'path': str(self.bob), 'type': 'age'}], self=self.bpub))
        self.app = App(self.box.config, self.gh)
        self.execute(['recipients', 'remove', 'TOKEN', self.apub])
        audience = self.app.read_policy(self.app.fetch('alice/vault'), 'TOKEN')
        self.assertEqual(audience['recipients'], [self.bpub])

    def test_same_value_replacement_is_noop(self):
        self.add('TOKEN')
        before = self.gh.current
        self.add('TOKEN', replace=True)
        self.assertEqual(self.gh.current, before)

    def test_dotenv_atomicity_and_recipient_preservation(self):
        self.add('EXISTING', recipients=[self.bpub])
        path = self.box.root / 'input.env'
        path.write_text('NEW=one\nEXISTING=two\n')
        before = self.gh.current
        with self.assertRaises(Error):
            self.execute(['import-env', str(path)])
        self.assertEqual(before, self.gh.current)
        self.execute(['import-env', str(path), '--replace', '--recipient', self.cpub])
        snap = self.app.fetch('alice/vault')
        self.assertEqual(set(self.app.read_policy(snap, 'EXISTING')['recipients']), {self.apub, self.bpub})
        self.assertEqual(set(self.app.read_policy(snap, 'NEW')['recipients']), {self.apub, self.cpub})

    def test_conflict_preserves_pending_encrypted_work(self):
        self.add('TOKEN')
        self.gh.fail = 'conflict'
        with self.assertRaises(Error) as error:
            self.add('NEW')
        self.assertIn('pending', str(error.exception))
        self.assertTrue((self.box.config.state / '123.pending.json').exists())
        self.assertNotIn(b'fixture', (self.box.config.state / '123.pending.json').read_bytes())
        with self.assertRaises(Error):
            self.add('ANOTHER')

    def test_projected_size_rejected_before_publication(self):
        self.add('TOKEN')
        snap = self.app.fetch('alice/vault')
        before = self.gh.current
        with patch('github_secrets.github.MAX_CACHE_BYTES', 1), self.assertRaises(Error):
            snap.publish({'secrets/TOKEN/value.sops.json': b'oversized-for-this-test'})
        self.assertEqual(self.gh.current, before)
        self.assertFalse((self.box.config.state / '123.pending.json').exists())

    def test_lost_push_response_is_resolved(self):
        self.gh.fail = 'lost-response'
        self.add('TOKEN')
        self.assertFalse((self.box.config.state / '123.pending.json').exists())
        self.assertIn('TOKEN', self.app.fetch('alice/vault').names)

    def test_offline_and_partial_discovery(self):
        self.add('TOKEN')
        with patch.object(self.gh, 'api', side_effect=AssertionError('Network in offline mode')):
            code, out, _ = self.execute(['secrets', 'list', '--offline', '--json'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)['items'][0]['offline'])
        self.gh.search_errors = ['Rate limited']
        code, out, _ = self.execute(['secrets', 'list', '--json'])
        self.assertEqual(code, 3)
        self.assertEqual(len(json.loads(out)['items']), 1)

    def test_unrelated_secret_is_not_an_error(self):
        self.add('TOKEN')
        self.box.use(self.bob)
        self.app = App(self.box.config, self.gh)
        code, out, _ = self.execute(['secrets', 'list', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['items'], [])

    def test_bad_policy_does_not_hide_good_secret(self):
        self.add('GOOD')
        self.add('BAD')
        self.gh.put({'secrets/BAD/recipients.json': b'{}'})
        code, out, _ = self.execute(['secrets', 'list', '--json'])
        self.assertEqual(code, 3)
        self.assertEqual([row['name'] for row in json.loads(out)['items']], ['GOOD'])

    def test_missing_ciphertext_does_not_hide_other_results(self):
        self.add('GOOD')
        self.add('BAD')
        api = self.gh.api
        def missing(endpoint, method='GET', body=None):
            result = api(endpoint, method, body)
            if '/git/trees/' in endpoint:
                result['tree'] = [entry for entry in result['tree'] if entry['path'] != 'secrets/BAD/value.sops.json']
            return result
        with patch.object(self.gh, 'api', side_effect=missing):
            code, out, _ = self.execute(['secrets', 'list', '--json'])
        self.assertEqual(code, 3)
        self.assertEqual([row['name'] for row in json.loads(out)['items']], ['GOOD'])

    def test_symlink_or_submodule_rejected(self):
        self.add('TOKEN')
        snap = self.app.fetch('alice/vault')
        for mode, kind in [('120000', 'blob'), ('160000', 'commit')]:
            tree = copy.deepcopy(snap.tree)
            tree['tree'][0]['mode'] = mode
            tree['tree'][0]['type'] = kind
            with self.assertRaises(Error):
                Snapshot(self.gh, self.box.config, snap.info, snap.commit, tree, snap.checked_at)

    def test_case_collisions_and_path_traversal(self):
        self.add('TOKEN')
        with self.assertRaises(Error):
            self.add('token')
        with self.assertRaises(Error):
            self.add('../outside')


class DiscoveryTests(unittest.TestCase):
    def test_empty_success_response_and_rate_limit_headers(self):
        gh = GitHub()
        with patch('github_secrets.github.run', return_value=b'HTTP/2.0 204 No Content\n\n'):
            self.assertEqual(gh.api('repos/a/b/git/refs/heads/test', 'DELETE'), {})
        with patch('github_secrets.github.run', return_value=(
                b'HTTP/2.0 200 OK\nx-ratelimit-remaining: 0\nx-ratelimit-reset: 9999999999\n\n{}')):
            gh.api('search/code?q=x')
            with self.assertRaises(Error):
                gh.api('search/code?q=y')


    def test_search_filters_paths_and_marks_incomplete(self):
        gh = GitHub()
        response = {'total_count': 3, 'incomplete_results': True, 'items': [
            {'path': 'secrets/TOKEN/recipients.json', 'repository': {'id': 1, 'full_name': 'a/b'}},
            {'path': 'secrets/OTHER/recipients.json', 'repository': {'id': 1, 'full_name': 'a/b'}},
            {'path': 'other/recipients.json', 'repository': {'id': 2, 'full_name': 'a/c'}}]}
        with patch.object(gh, 'api', return_value=response) as api:
            repos, errors = gh.search([run(['age-keygen', '-y'], run(['age-keygen'])).decode().strip()])
        self.assertEqual(repos, ['a/b'])
        self.assertTrue(errors)
        self.assertIn('filename%3Arecipients.json', api.call_args.args[0])
