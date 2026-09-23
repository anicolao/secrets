"""Secret input only through data channels. SPDX-License-Identifier: GPL-3.0-only."""
import getpass
import os
import re
import sys
import warnings
from .common import Error, MAX_VALUE, name, read_limited, require


def hidden(prompt):
    require(sys.stdin.isatty(), 'A terminal is required; use --stdin, --file, or --from-env.')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except (getpass.GetPassWarning, EOFError):
            raise Error('Cannot read hidden input from a terminal.') from None


def read_value(args):
    if args.from_env is not None:
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', args.from_env), 'Invalid environment variable name.', 2)
        require(args.from_env in os.environ, 'Requested environment variable is unset.')
        value = os.environ.pop(args.from_env).encode('utf-8')
    elif args.file is not None:
        value = read_limited(args.file, MAX_VALUE)
    elif args.stdin:
        value = sys.stdin.buffer.read(MAX_VALUE + 1)
    else:
        value = hidden('Secret value: ').encode('utf-8')
    require(len(value) <= MAX_VALUE, 'Secret exceeds 1 MiB limit.')
    return value


def dotenv(raw):
    """Deliberately small data-only grammar; no interpolation, evaluation, or shell."""
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise Error('Dotenv input must be UTF-8.') from None
    result = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            match = re.fullmatch(r'(?:export\s+)?([A-Za-z][A-Za-z0-9_-]{0,63})\s*=(.*)', line)
            require(match is not None, 'Invalid entry.')
            key, value = match.groups()
            value = '' if value[:1].isspace() and value.lstrip().startswith('#') else value.lstrip()
            name(key)
            require(key not in result, 'Duplicate entry.')
            if value.startswith(('"', "'")):
                quote, rest = value[0], value[1:]
                chars, index, ended = [], 0, False
                while index < len(rest):
                    char = rest[index]
                    if char == quote:
                        require(not rest[index+1:].strip() or rest[index+1:].lstrip().startswith('#'), 'Trailing content.')
                        ended = True
                        break
                    if quote == '"' and char == '\\':
                        index += 1
                        require(index < len(rest), 'Invalid escape.')
                        escapes = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"'}
                        require(rest[index] in escapes, 'Unsupported escape.')
                        char = escapes[rest[index]]
                    chars.append(char)
                    index += 1
                require(ended, 'Unterminated quote.')
                value = ''.join(chars)
            else:
                value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
            result[key] = value.encode('utf-8')
        except Error:
            raise Error(f'Invalid or duplicate dotenv entry at line {number}.', 2) from None
    require(result, 'Dotenv input has no entries.', 2)
    require(len({key.casefold() for key in result}) == len(result), 'Case-colliding dotenv names.', 2)
    return result
