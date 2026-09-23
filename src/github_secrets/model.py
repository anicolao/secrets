"""Vault schema and removal evidence. SPDX-License-Identifier: GPL-3.0-only."""
import base64
import binascii
import copy
import datetime as dt
import uuid
from .common import Error, MAX_VALUE, fields, discovery_token, name, recipients, recipient, require

MARKER = {'format': 'github-sops-vault', 'version': 1}
REMOVAL_WARNING = (
    'Removing a recipient does not revoke the secret. They may retain plaintext or decrypt old Git revisions. '
    'This operation changes current encryption recipients and the encryption key; it does not change the '
    'secret value or invalidate a live credential. Generate a fresh replacement after removal and revoke '
    'the old credential at its issuer where applicable.'
)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def timestamp(value):
    require(isinstance(value, str) and value.endswith('Z'), 'Expected a UTC RFC 3339 timestamp.', 2)
    try:
        result = dt.datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        raise Error('Invalid UTC timestamp.', 2) from None
    return result


def validate_id(value):
    try:
        require(str(uuid.UUID(value)) == value, 'Invalid lifecycle UUID.')
    except (ValueError, TypeError, AttributeError):
        raise Error('Invalid lifecycle UUID.') from None


def policy(secret_name, audience):
    audience = recipients(audience)
    result = {'format': 'github-sops-secret', 'version': 1, 'name': name(secret_name),
              'recipients': audience}
    if any(key.startswith('ssh-rsa ') for key in audience):
        result.update(version=2, search_tokens=sorted(discovery_token(key) for key in audience))
    return result


def validate_policy(obj, secret_name):
    require(isinstance(obj, dict), 'Invalid recipient record.')
    version = obj.get('version')
    fields(obj, ('format', 'version', 'name', 'recipients', 'search_tokens') if version == 2
           else ('format', 'version', 'name', 'recipients'))
    require(obj['format'] == 'github-sops-secret' and type(version) is int and version in (1, 2),
            'Unsupported secret format.')
    require(obj['name'] == name(secret_name), 'Secret name does not match directory.')
    audience = recipients(obj['recipients'])
    require(all(recipient(key) == key for key in obj['recipients']), 'Noncanonical recipient.')
    if version == 1:
        require(all(key.startswith('age1') for key in audience), 'RSA requires a version 2 record.')
    else:
        require(obj['search_tokens'] == sorted(discovery_token(key) for key in audience),
                'Search tokens do not match recipient keys.')
    return obj


def validate_lifecycle(obj):
    fields(obj, ('sequence', 'generation', 'removals'))
    seq = obj['sequence']
    require(type(seq) is int and seq > 0, 'Invalid lifecycle sequence.')
    gen = obj['generation']
    fields(gen, ('id', 'introduced_sequence', 'recorded_at', 'generated_at', 'generation_evidence'))
    validate_id(gen['id'])
    intro = gen['introduced_sequence']
    require(type(intro) is int and 1 <= intro <= seq, 'Invalid generation sequence.')
    recorded = timestamp(gen['recorded_at'])
    if gen['generated_at'] is None:
        require(gen['generation_evidence'] == 'unknown', 'Invalid generation evidence.')
    else:
        require(gen['generation_evidence'] == 'user-asserted', 'Invalid generation evidence.')
        require(timestamp(gen['generated_at']) <= recorded, 'Generation time is after recording time.')
    require(isinstance(obj['removals'], list), 'Invalid removal history.')
    ids, last_seq = set(), 0
    for event in obj['removals']:
        fields(event, ('event_id', 'recipient', 'removed_at', 'sequence', 'generation_id_at_removal'))
        validate_id(event['event_id'])
        validate_id(event['generation_id_at_removal'])
        recipient(event['recipient'])
        timestamp(event['removed_at'])
        require(type(event['sequence']) is int and last_seq < event['sequence'] <= seq,
                'Invalid removal order.')
        require(event['event_id'] not in ids, 'Duplicate removal event.')
        if event['sequence'] >= intro:
            require(event['generation_id_at_removal'] == gen['id'], 'Inconsistent removal generation.')
        else:
            require(event['generation_id_at_removal'] != gen['id'], 'Inconsistent generation reference.')
        last_seq = event['sequence']
        ids.add(event['event_id'])
    return obj


def lifecycle_status(obj):
    result = {'generation': None, 'last_removed_at': None, 'removal_status': 'unknown',
              'unresolved_removal_event_ids': []}
    try:
        validate_lifecycle(obj)
    except (Error, TypeError, KeyError):
        return result
    gen, events = obj['generation'], obj['removals']
    result['generation'] = gen
    if not events:
        result['removal_status'] = 'no-removals-recorded'
        return result
    result['last_removed_at'] = events[-1]['removed_at']
    needed, uncertain, last_time = [], [], None
    for event in events:
        removed = timestamp(event['removed_at'])
        generated = timestamp(gen['generated_at']) if gen['generated_at'] else None
        clock_anomaly = last_time is not None and removed < last_time
        if event['sequence'] >= gen['introduced_sequence'] or (generated is not None and generated <= removed):
            needed.append(event['event_id'])
        elif generated is None or clock_anomaly or timestamp(gen['recorded_at']) <= removed:
            uncertain.append(event['event_id'])
        last_time = removed
    result['unresolved_removal_event_ids'] = needed + uncertain
    result['removal_status'] = 'rotation-needed' if needed else ('unknown' if uncertain else 'replacement-recorded')
    return result


def payload_value(obj, secret_name):
    require(isinstance(obj, dict), 'Invalid secret payload.')
    require(set(obj) in ({'schema', 'name', 'encoding', 'value'},
                         {'schema', 'name', 'encoding', 'value', 'lifecycle'}), 'Unexpected payload fields.')
    require(type(obj['schema']) is int and obj['schema'] == 1 and obj['name'] == secret_name
            and obj['encoding'] == 'base64', 'Invalid secret payload schema or name.')
    try:
        value = base64.b64decode(obj['value'], validate=True)
    except (ValueError, TypeError, binascii.Error):
        raise Error('Invalid secret byte encoding.') from None
    require(len(value) <= MAX_VALUE, 'Secret exceeds size limit.')
    return value


def new_payload(secret_name, value, previous=None, generated_at=None, time=None):
    time = time or now()
    require(len(value) <= MAX_VALUE, 'Secret exceeds size limit.')
    if generated_at is not None:
        require(timestamp(generated_at) <= timestamp(time), 'Generation time cannot be in the future.', 2)
    if previous is not None:
        validate_lifecycle(previous.get('lifecycle'))
        if payload_value(previous, secret_name) == value:
            require(generated_at is None, 'Unchanged values cannot receive a new generation time.', 2)
            return None
        sequence = previous['lifecycle']['sequence'] + 1
        removals = copy.deepcopy(previous['lifecycle']['removals'])
    else:
        sequence, removals = 1, []
    return {'schema': 1, 'name': name(secret_name), 'encoding': 'base64',
            'value': base64.b64encode(value).decode('ascii'),
            'lifecycle': {'sequence': sequence,
                          'generation': {'id': str(uuid.uuid4()), 'introduced_sequence': sequence,
                                         'recorded_at': time, 'generated_at': generated_at,
                                         'generation_evidence': 'user-asserted' if generated_at else 'unknown'},
                          'removals': removals}}


def changed_recipients(payload, removed=None, time=None):
    validate_lifecycle(payload.get('lifecycle'))
    result = copy.deepcopy(payload)
    life = result['lifecycle']
    life['sequence'] += 1
    if removed:
        life['removals'].append({'event_id': str(uuid.uuid4()), 'recipient': recipient(removed),
                                 'removed_at': time or now(), 'sequence': life['sequence'],
                                 'generation_id_at_removal': life['generation']['id']})
    return result
