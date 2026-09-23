"""Command interface. SPDX-License-Identifier: GPL-3.0-only."""
import argparse
import json
import os
import signal
import sys
from pathlib import Path
from .common import (Error, MAX_DOCUMENT, MAX_RECORD, MAX_SECRETS, json_bytes, name,
                     parse_json, read_limited, recipient, repo_name, require)
from .config import Config
from .crypto import Crypto, Identities
from .github import GitHub, Snapshot
from .inputs import dotenv, read_value
from .model import (MARKER, REMOVAL_WARNING, changed_recipients, lifecycle_status, new_payload,
                    payload_value, policy, timestamp, validate_policy)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid values, including accidental plaintext arguments.
        raise Error('Invalid command or arguments. Use --help; secret values must use an input source.', 2)


def parser():
    root = Parser(prog='secrets', description='Per-secret SOPS vaults on GitHub.')
    root.add_argument('--version', action='version', version='secrets 0.1.0')
    commands = root.add_subparsers(dest='command', required=True)
    identity = commands.add_parser('identity').add_subparsers(dest='action', required=True)
    add_identity = identity.add_parser('add')
    add_identity.add_argument('path')
    add_identity.add_argument('--type', choices=('age', 'ssh-ed25519'), required=True)
    identity.add_parser('show')
    identity.add_parser('default').add_argument('recipient')
    create = commands.add_parser('create')
    create.add_argument('name')
    create.add_argument('--owner')
    visibility = create.add_mutually_exclusive_group()
    visibility.add_argument('--public', action='store_true')
    visibility.add_argument('--private', action='store_true')
    vaults = commands.add_parser('vaults').add_subparsers(dest='action', required=True)
    for verb in ('add', 'default'):
        vaults.add_parser(verb).add_argument('repo')
    listing = vaults.add_parser('list')
    list_flags(listing)
    secrets = commands.add_parser('secrets').add_subparsers(dest='action', required=True)
    listing = secrets.add_parser('list')
    list_flags(listing)
    listing.add_argument('--vault')
    add = commands.add_parser('add')
    add.add_argument('name')
    source = add.add_mutually_exclusive_group()
    source.add_argument('--stdin', action='store_true')
    source.add_argument('--file')
    source.add_argument('--from-env')
    write_flags(add)
    imp = commands.add_parser('import-env')
    imp.add_argument('path')
    imp.add_argument('--key', action='append', default=[])
    write_flags(imp)
    get = commands.add_parser('get')
    get.add_argument('name')
    get.add_argument('--vault')
    get.add_argument('--offline', action='store_true')
    recips = commands.add_parser('recipients').add_subparsers(dest='action', required=True)
    for verb in ('list', 'add', 'remove'):
        sub = recips.add_parser(verb)
        sub.add_argument('name')
        sub.add_argument('--vault')
        if verb != 'list':
            sub.add_argument('recipient')
    return root


def list_flags(command):
    command.add_argument('--offline', action='store_true')
    command.add_argument('--json', action='store_true')


def write_flags(command):
    command.add_argument('--vault')
    command.add_argument('--recipient', action='append', default=[])
    command.add_argument('--replace', action='store_true')
    command.add_argument('--generated-at')


def report_status(payload, prefix=''):
    status = lifecycle_status(payload.get('lifecycle'))
    if status['removal_status'] in ('unknown', 'rotation-needed'):
        print(prefix + status['removal_status'] + ': a former recipient may still know this value; '
              'freshness or removal evidence is unresolved. Revoke old credentials at the issuer where applicable.', file=sys.stderr)
    return status


class App:
    def __init__(self, config=None, github=None):
        self.config = config or Config()
        self.github = github or GitHub()
        self.identities = Identities(self.config)
        self.crypto = Crypto(self.identities)

    def destination(self, explicit):
        result = explicit or self.config.data['default']
        require(result, 'No default vault; use --vault or vaults default.', 2)
        return repo_name(result)

    def fetch(self, repo, offline=False):
        snap = Snapshot.fetch(self.github, self.config, repo, offline)
        if not offline:
            self.config.register(snap.info)
        return snap

    def read_policy(self, snap, secret):
        return validate_policy(parse_json(snap.read(f'secrets/{secret}/recipients.json'), MAX_RECORD), secret)

    def read_secret(self, snap, secret, only=None):
        audience = self.read_policy(snap, secret)
        return audience, self.crypto.decrypt(snap.read(f'secrets/{secret}/value.sops.json'), audience, only)

    def execute(self, args):
        if args.command == 'identity':
            return self.identity(args)
        if args.command == 'create':
            return self.create(args)
        if args.command == 'vaults' and args.action != 'list':
            snap = self.fetch(repo_name(args.repo))
            if args.action == 'default':
                self.config.update(lambda data: data.update(default=snap.info['full_name']))
            print(snap.info['full_name'])
            return 0
        if args.command in ('vaults', 'secrets'):
            return self.listing(args)
        if args.command == 'get':
            secret = name(args.name)
            snap = self.fetch(self.destination(args.vault), args.offline)
            _, payload = self.read_secret(snap, secret)
            report_status(payload)
            if args.offline:
                print(f'Offline snapshot {snap.revision}, checked {snap.checked_at}', file=sys.stderr)
            sys.stdout.buffer.write(payload_value(payload, secret))
            return 0
        if args.command == 'recipients' and args.action == 'list':
            snap = self.fetch(self.destination(args.vault))
            audience = self.read_policy(snap, name(args.name))
            print(json.dumps({'recipients': audience['recipients'], 'removal_status': 'unknown',
                              'note': 'Public policy only; use secrets list to verify lifecycle evidence.'}, indent=2))
            return 0
        return self.write(args)

    def identity(self, args):
        if args.action == 'add':
            source = {'path': str(Path(args.path).expanduser().absolute()), 'type': args.type}
            pairs = self.identities.load_source(source)
            def change(data):
                if source not in data['identities']:
                    first = not data['identities']
                    data['identities'].append(source)
                    if first:
                        data['self'] = pairs[0][0] if len(pairs) == 1 else None
            self.config.update(change)
            print('\n'.join(pair[0] for pair in pairs))
        elif args.action == 'default':
            selected = recipient(args.recipient)
            self.identities.load()
            require(selected in self.identities.public, 'Recipient has no registered identity.', 2)
            self.config.update(lambda data: data.update(self=selected))
            print(selected)
        else:
            self.identities.load()
            try:
                selected = self.identities.self_recipient()
            except Error:
                selected = None
            print(json.dumps({'recipients': self.identities.public, 'self': selected}, indent=2))
        return 0

    def create(self, args):
        require('/' not in args.name, 'Use a repository name and optional --owner.', 2)
        owner = args.owner or self.github.api('user')['login']
        repo = repo_name(owner + '/' + args.name)
        info = self.github.create(repo, args.public)
        try:
            with self.config.lock(info['id']):
                snap = Snapshot.fetch(self.github, self.config, repo, allow_empty=True)
                revision = snap.publish({'vault.json': json_bytes(MARKER), 'README.md': (
                    '# Encrypted vault\n\nEach secrets/NAME directory contains searchable recipients.json and '
                    'a value.sops.json encrypted independently with SOPS/age. Values and lifecycle evidence are '
                    'encrypted; names and current recipients are visible to repository readers. '
                    'Recipient removal does not revoke existing copies or service credentials.\n').encode()})
            self.config.register(info, choose_default=True)
        except Error:
            print(f'Repository created at https://github.com/{repo}, but vault initialization failed; '
                  'inspect its default branch and pending state before retrying.', file=sys.stderr)
            raise
        print(f'https://github.com/{repo} ({"public" if args.public else "private"}) {revision}')
        return 0

    def write(self, args):
        if hasattr(args, 'name'):
            name(args.name)
        if args.command == 'add':
            require(not (args.replace and args.recipient), '--replace preserves recipients; use recipients add/remove.', 2)
        if args.command in ('add', 'import-env'):
            for public in args.recipient:
                recipient(public)
            if args.generated_at:
                timestamp(args.generated_at)
        else:
            recipient(args.recipient)
        repo = self.destination(args.vault)
        info = self.github.info(repo)
        with self.config.lock(info['id']):
            require(not (self.config.state / (str(info['id']) + '.pending.json')).exists(),
                    'Unresolved publication exists; inspect pending state and the recovery guide.')
            snap = self.fetch(repo)
            self.identities.load()
            if args.command == 'recipients':
                changes, payload = self.recipient_change(snap, args)
                outputs = {args.name: payload}
            else:
                values = self.values(snap, args)
                changes, outputs = self.value_changes(snap, args, values)
            if not changes:
                print('No change; generation history and removal warnings preserved.')
                for secret, payload in outputs.items():
                    report_status(payload, secret + ': ')
                return 0
            revision = snap.publish(changes)
            # Refresh the snapshot and ciphertext cache for immediate offline use.
            try:
                fresh = self.fetch(repo)
                for path in changes:
                    fresh.read(path)
            except Error:
                print('Publication succeeded; local cache refresh failed.', file=sys.stderr)
            print(f'Published {snap.info["full_name"]} {revision}')
            for secret, payload in outputs.items():
                report_status(payload, secret + ': ')
            if args.command == 'recipients' and args.action == 'remove':
                event = payload['lifecycle']['removals'][-1]
                generation = payload['lifecycle']['generation']['generated_at'] or 'unknown'
                print(f'Recipient {args.recipient} removed from current encryption at {event["removed_at"]}; '
                      f'value generated: {generation}. Existing copies may still work. Revision {revision}', file=sys.stderr)
        return 0

    def values(self, snap, args):
        if args.command == 'add':
            existing = args.name in snap.names
            require(not existing or args.replace, 'Secret already exists; use --replace.', 2)
            require(existing or not args.replace, 'Cannot replace a missing secret.', 2)
            return {args.name: read_value(args)}
        result = dotenv(read_limited(args.path, MAX_DOCUMENT))
        if args.key:
            require(len(args.key) == len(set(args.key)), 'Duplicate --key.', 2)
            for selected in args.key:
                name(selected)
                require(selected in result, 'Selected dotenv key is absent.', 2)
            result = {key: result[key] for key in args.key}
        return result

    def value_changes(self, snap, args, values):
        require(len(set(snap.names) | set(values)) <= MAX_SECRETS, 'Too many secrets.')
        combined = set(snap.names) | set(values)
        require(len({key.casefold() for key in combined}) == len(combined), 'Case-colliding secret names.', 2)
        plans = []
        for secret, value in values.items():
            name(secret)
            old = None
            if secret in snap.names:
                require(args.replace, 'Import would replace an existing secret; use --replace.', 2)
                audience, old = self.read_secret(snap, secret)
            else:
                audience = policy(secret, sorted(set([self.identities.self_recipient()] + args.recipient)))
            updated = new_payload(secret, value, old, args.generated_at)
            plans.append((secret, audience, old, updated))
        # Validate the whole batch before encryption; publish all pairs in a single commit.
        changes, outputs = {}, {}
        for secret, audience, old, updated in plans:
            outputs[secret] = updated or old
            if updated is not None:
                changes[f'secrets/{secret}/recipients.json'] = json_bytes(audience)
                changes[f'secrets/{secret}/value.sops.json'] = self.crypto.encrypt(updated, audience)
        return changes, outputs

    def recipient_change(self, snap, args):
        audience = self.read_policy(snap, args.name)
        raw = snap.read(f'secrets/{args.name}/value.sops.json')
        acting, payload = None, None
        selected = self.config.data.get('self')
        candidates = sorted(self.identities.public, key=lambda public: public != selected)
        for public in candidates:
            if public in audience['recipients']:
                try:
                    payload = self.crypto.decrypt(raw, audience, only=public)
                    acting = public
                    break
                except Error:
                    continue
        require(acting is not None, 'No local identity can decrypt this secret.')
        new = set(audience['recipients'])
        if args.action == 'add':
            require(args.recipient not in new, 'Recipient is already present.', 2)
            new.add(args.recipient)
        else:
            require(args.recipient in new, 'Recipient is not present.', 2)
            require(args.recipient != acting and len(new) > 1, 'Cannot remove the acting or final recipient.', 2)
            print(REMOVAL_WARNING, file=sys.stderr)
            new.remove(args.recipient)
        print('Current recipients: ' + ', '.join(audience['recipients']), file=sys.stderr)
        print('Proposed recipients: ' + ', '.join(sorted(new)), file=sys.stderr)
        updated = changed_recipients(payload, args.recipient if args.action == 'remove' else None)
        audience = policy(args.name, sorted(new))
        return {f'secrets/{args.name}/recipients.json': json_bytes(audience),
                f'secrets/{args.name}/value.sops.json': self.crypto.encrypt(updated, audience)}, updated

    def listing(self, args):
        self.identities.load()
        explicit = getattr(args, 'vault', None)
        repos = [repo_name(explicit)] if explicit else [item['name'] for item in self.config.data['vaults'].values()]
        errors = []
        if not args.offline and not explicit:
            found, errors = self.github.search(self.identities.public)
            repos.extend(found)
        items, seen = [], set()
        for repo in sorted(set(repos)):
            try:
                snap = self.fetch(repo, args.offline)
                if snap.info['id'] in seen:
                    continue
                seen.add(snap.info['id'])
                rows, matched, failures = [], 0, 0
                for secret in snap.names:
                    try:
                        audience = self.read_policy(snap, secret)
                        if not set(audience['recipients']) & set(self.identities.public):
                            continue
                        matched += 1
                        payload = self.crypto.decrypt(snap.read(f'secrets/{secret}/value.sops.json'), audience)
                        status = lifecycle_status(payload.get('lifecycle'))
                        rows.append({'vault': snap.info['full_name'], 'name': secret, 'revision': snap.revision,
                                     'checked_at': snap.checked_at, 'offline': args.offline,
                                     'verification': 'verified-readable', **status})
                    except Error as exc:
                        failures += 1
                        errors.append(f'{repo}/{secret}: {exc}')
                if args.command == 'secrets':
                    items.extend(rows)
                else:
                    status = ('partial' if rows else 'unreadable') if failures else (
                        'verified-readable' if rows else ('known-empty' if not snap.names else 'known-no-matches'))
                    items.append({'vault': snap.info['full_name'], 'revision': snap.revision,
                                  'checked_at': snap.checked_at, 'offline': args.offline,
                                  'verification': status, 'matched': matched, 'readable': len(rows),
                                  'failed': failures, 'unresolved_removals': sum(
                                      row['removal_status'] in ('unknown', 'rotation-needed') for row in rows)})
            except Error as exc:
                errors.append(f'{repo}: {exc}')
        result = {'version': 1, 'items': items, 'errors': errors, 'partial': bool(errors), 'discovery_complete': False}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for row in items:
                if 'name' in row:
                    generation = row['generation'] or {}
                    print(f'{row["vault"]}/{row["name"]}\t{row["removal_status"]}\t'
                          f'generated={generation.get("generated_at") or "unknown"}\t'
                          f'last_removed={row["last_removed_at"] or "none"}\t{row["revision"]}')
                else:
                    print(f'{row["vault"]}\t{row["verification"]}\treadable={row["readable"]}\t'
                          f'unresolved={row["unresolved_removals"]}\t{row["revision"]}')
                if args.offline:
                    print(f'Offline snapshot checked {row["checked_at"]}', file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            print('Discovery is best effort; use vaults add OWNER/REPO for known vaults.', file=sys.stderr)
        return 3 if errors else 0


def main(argv=None):
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    old_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        # Parse before local state, tools, or network; malformed arguments are never echoed.
        args = parser().parse_args(argv)
        os.umask(0o077)
        return App().execute(args)
    except Error as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        print('Operation failed: invalid data or unavailable local state. No secret details were logged.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Cancelled.', file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, old_handler)


if __name__ == '__main__':
    sys.exit(main())
