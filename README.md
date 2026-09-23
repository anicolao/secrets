# Secrets

A command-line secrets manager built from Nix flakes, SOPS, age, and GitHub. Each vault is a GitHub repository containing encrypted secrets and a searchable public recipient record for each secret. A local command creates vaults, stores secrets, discovers secrets addressed to you, and lists the secrets you can decrypt.

**Status: MVP (0.1.0).** The flake and CLI implement per-secret encryption, GitHub publication and discovery, SSH-derived identities, dotenv imports, and removal-history warnings. Licensed under [GPLv3](LICENSE).

## The idea

By default, the application uses your existing `~/.ssh/id_ed25519` private key as its identity source. It derives a stable native `age1…` public recipient, which you share with others and search for on GitHub. Each secret has its own explicit recipient list; its value is encrypted for those recipients before publication.

In age terminology, a **recipient** is public and an **identity** is private. Only recipients belong in a vault repository; identities never do. See the [age manual](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn).

Per-secret recipients are part of version 1. A single vault can contain a personal token, a token shared with Bob, and another shared with Carol. Access to one secret grants no encryption access to the others. A vault is an organizational and publishing container.

## Getting started

Prerequisites are Nix with flakes enabled, a GitHub account authenticated through `gh`, and an existing local Ed25519 SSH private key (or an explicitly configured native age identity). The flake supplies the application's runtime tools. You retain responsibility for backing up your identity; GitHub login cannot recover it.

```sh
# Authenticate once if you have not already configured gh.
nix develop --command gh auth login

# Uses ~/.ssh/id_ed25519 automatically; no separate age key setup required.
nix run . -- identity show

# Create a GitHub repository; the first vault becomes the local default.
nix run . -- create personal

# Public vaults support discovery by recipients without a repository invitation.
nix run . -- create shared-demo --public

# Select the destination for unqualified writes.
nix run . -- vaults default OWNER/personal

# Prompt for a secret without putting its value in shell history.
nix run . -- add API_TOKEN

# A new secret includes you; repeat --recipient to share that secret with others.
nix run . -- add TEAM_TOKEN --recipient age1BOB_PUBLIC_RECIPIENT

# Or consume exact bytes from standard input, including embedded newlines.
nix run . -- add SERVICE_CONFIG --stdin < /path/to/private/config.json

# Import a variable by name, or parse selected dotenv entries as separate secrets.
nix run . -- add DEPLOY_TOKEN --from-env SERVICE_API_TOKEN
nix run . -- import-env /path/to/private/app.env --key DATABASE_URL --key API_KEY

# Find vaults containing secrets addressed to your derived or configured age recipients.
nix run . -- vaults list

# List names of secrets successfully decrypted, without showing values.
nix run . -- secrets list

# Read one secret from the default vault, writing its exact value to stdout.
nix run . -- get API_TOKEN
nix run . -- get API_TOKEN --vault OWNER/personal
```

`create` defaults to a private repository. Use `--public` deliberately: public vaults expose names, recipients, membership relationships, and encrypted history. Secret values remain encrypted. Recipients of secrets in private vaults also need GitHub permission to fetch the repository.

`add` accepts values through a hidden prompt, `--stdin`, `--file PATH`, or `--from-env VARIABLE_NAME`. Positional values and secret-value flags are rejected before any network operation; the error never echoes the rejected argument. Environment input passes only the variable name, never its expanded value, in arguments. `import-env PATH` imports selected `.env` entries as separate secrets without executing the file. For stdin, pipe a producer or redirect a file rather than typing a literal secret into a shell command. A successful write means the encrypted commit reached the remote default branch, not merely saved locally. Existing secret names require `--replace`.

## Sharing and choosing vaults

```sh
# Create the secret in this vault first (hidden prompt).
nix run . -- add API_TOKEN --vault OWNER/shared-demo

# RECIPIENT is the other person's complete, independently verified public age key.
nix run . -- recipients add API_TOKEN RECIPIENT --vault OWNER/shared-demo

# Register a known repository immediately, without waiting for search indexing.
nix run . -- vaults add OWNER/shared-demo

# Inspect only one vault.
nix run . -- secrets list --vault OWNER/shared-demo

# Remove a recipient from current encryption; copies and the value remain unchanged.
nix run . -- recipients remove API_TOKEN RECIPIENT --vault OWNER/shared-demo
```

Recipient changes require GitHub write permission and the ability to decrypt the named secret. Adding a recipient shares that secret’s current value and subsequent replacements. Other secrets and their recipients stay unchanged. New secrets default to you plus any explicit `--recipient` values; replacements preserve the existing list. The example `age1BOB_PUBLIC_RECIPIENT` is a placeholder for a complete valid public key. GitHub collaborator permissions remain separately managed through GitHub; changing encryption recipients does not change repository membership.

**Removal does not revoke a secret.** The command always warns that the former recipient may retain plaintext or decrypt old Git revisions. It changes current encryption recipients and rotates the data key; it does not change the value or invalidate a live credential. After removal, generate a fresh value, invalidate the old credential at its issuer where applicable, and publish the replacement.

Each secret tracks value generation separately from recipient removal. Encrypted metadata preserves removal times and the value version present at each removal. `secrets list` shows the reported generation time, last removal time, and whether a former recipient may still know the current value. Re-encryption or saving the same bytes does not reset this warning.

Actual generation time is unknown unless explicitly supplied. For a freshly generated replacement, use a hidden prompt or file input and record its real generation time (the timestamp below is illustrative):

```sh
nix run . -- add API_TOKEN --replace --generated-at 2026-09-23T18:00:00Z --vault OWNER/shared-demo
```

The UI reports `rotation-needed` when removal occurred after the current value was introduced, `unknown` when freshness cannot be established, and `replacement-recorded` when the user reports a fresh value generated after all recorded removals. Merely storing different bytes is insufficient to establish freshness. Even `replacement-recorded` does not verify external credential revocation or prove that nobody has a copy. With no recorded removals, the UI says `no-removals-recorded`, never “secure.”

The default vault is a local preference, never a search result chosen implicitly. `--vault OWNER/REPO` overrides it. Secret names are unique within a vault; cross-vault listings always include `OWNER/REPO` so duplicate names are unambiguous.

## What a vault contains

```text
vault.json                  # Vault format marker; no vault-wide recipient policy
secrets/
  API_TOKEN/
    recipients.json         # Small searchable record with complete age1… recipients
    value.sops.json          # Value encrypted only for this secret’s recipients
  SERVICE_CONFIG/
    recipients.json
    value.sops.json
README.md                   # Generated explanation of the vault format
```

SOPS manages the encrypted files, with age recipients protecting access to their data keys. This project adds the manifest, GitHub workflow, and command interface; it does not invent a cryptographic format. See the [SOPS documentation](https://getsops.io/docs/).

Each `recipients.json` is searchable metadata and the intended policy for its sibling ciphertext. Actual readability is established by successful decryption and integrity verification. A search hit alone does not establish access or prove who published the contents.

## Discovery and listing

`secrets list` searches GitHub for your full `age1…` recipient in `recipients.json` files, validates each matching secret at the current default-branch revision, and lists the names it can decrypt. It also scans known vaults, so you can use a repository before search indexes it. `vaults list` groups these addressed secrets by repository; registered empty vaults are shown separately as known containers. Neither command prints secret values.

You can also search GitHub manually for `"YOUR_COMPLETE_AGE_RECIPIENT" filename:recipients.json`. Obtain that public address with `nix run . -- identity show`. A match points directly to a secret’s recipient record, even when its ciphertext is too large for code search.

Discovery is best effort. GitHub indexes the default branch, applies search limits, and can return incomplete results. Private results depend on the authenticated account's repository access. See [GitHub's search API documentation](https://docs.github.com/en/rest/search/search#search-code). The CLI must report partial results and failures rather than treating them as an empty inventory. Explicit registration with `vaults add` is the reliable fallback for a known repository.

The promise is “find and verify accessible secrets in known and discoverable vaults,” not an exhaustive census of GitHub. Recently created vaults remain usable immediately through their repository address.

## SSH identity default

The application uses [ssh-to-age](https://github.com/Mic92/ssh-to-age) to convert Ed25519 SSH keys to native age keys. It derives the private identity only at runtime, without persisting a separate age key. This is distinct from encrypting directly to an `ssh-ed25519 …` recipient; this format consistently publishes the derived `age1…` address.

Use `identity add PATH --type ssh-ed25519` for another SSH key path, or `identity add PATH --type age` for native age identities. Passphrase-protected SSH keys prompt privately when needed. RSA, ECDSA, and agent-only or hardware-held SSH keys are outside the initial conversion path and produce a clear unsupported-key error. SSH authentication key replacement does not migrate encrypted secrets: retain the old key until affected secrets have been rekeyed.

## Boundaries

Plaintext and private keys stay outside Git repositories and the Nix store. Decryption happens at runtime on the user's machine. Vault contents are treated as data: reading a vault never evaluates its Nix files or executes repository hooks or scripts.

Encryption protects stored secret values from readers without an authorized identity. It does not hide public metadata, protect a compromised endpoint, prevent an authorized reader from copying values, authenticate a publisher through encryption alone, or recover a lost private key. Writers are trusted to maintain the recipient policy. The MVP has no server, browser interface, or automatic service credential rotation.

## Design documents

- [VISION.md](VISION.md) explains the user experience, principles, tradeoffs, and longer-term direction.
- [MVP_DESIGN.md](MVP_DESIGN.md) specifies the commands, repository schema, local state, transactions, discovery algorithm, and acceptance criteria.

## Development and validation

```sh
nix flake check --print-build-logs
nix run . -- --help
nix develop --command env PYTHONPATH=src python -m unittest discover -s tests -v
```

The offline test suite generates disposable keys and exercises real SOPS, age, and SSH conversion, plus a simulated GitHub Git object store for publication conflicts and failures. CI runs the Nix check on Linux and macOS. A separate opt-in live test creates and removes a temporary branch in a specified repository using fake values:

```sh
nix develop --command env PYTHONPATH=src python scripts/live_smoke.py OWNER/REPO
```

This checks real GitHub commits, reads, recipient removal, historical decryption, and search-query acceptance. It does not verify search indexing of a new default-branch vault; GitHub controls indexing and coverage. Explicit registration works independently of indexing. Initial local validation was on Apple Silicon macOS; the flake also declares Intel macOS and both Linux architectures. Intel macOS uses a separately pinned Nixpkgs 26.05 input because the unstable input no longer supports that platform.

## Publication and recovery

Writes use GitHub’s Git database API to create encrypted blobs, a tree, and a commit based on the fetched revision. A non-force branch update publishes the whole change atomically. Concurrent changes are rejected; repository branch protections still apply. No checkout, hook, filter, script, or flake from a vault is executed.

If publication fails or its outcome cannot be established, encrypted pending work remains under `$XDG_STATE_HOME/secrets/REPOSITORY_ID.pending.json` (default `~/.local/state/secrets`). Further writes to that vault stop until this is resolved. The file records the base revision, proposed commit if one was created, and base64-encoded ciphertext and public recipient records. It contains no plaintext value or private key.

1. Check the repository’s current default-branch revision on GitHub. Compare it with the pending `commit`; GitHub’s compare view can establish whether that commit is an ancestor of the current revision.
2. If the commit landed, move the pending file into a private archive outside the active state directory and refresh the vault. If it did not land, retain the file as a recovery artifact, then move it out of the active directory before retrying from current remote state.
3. Re-run the original operation with its input source after reviewing any policy changes. Do not force-update the branch or blindly copy the old recipient record over a newer one. To recover an unpublished value, decode its pending `value.sops.json` into a private scratch location and decrypt with SOPS and an authorized identity; its inner `value` is base64-encoded.

A created repository whose vault initialization failed is retained and reported. Repair its marker from pending work or initialize it deliberately before registering it; `create` never adopts or deletes an existing repository automatically.

## Input and runtime limits

`--from-env` reads an existing variable; an unset name is an error and an empty value is valid. Do not expand a variable into a command argument. Only GitHub authentication variables are passed to `gh`; arbitrary value variables and SOPS hooks are removed from child environments. The source file or parent environment remains the caller’s responsibility.

Dotenv import supports single-line assignments, optional `export`, blank lines, comments, and single/double quotes. Double-quoted values support `\n`, `\r`, `\t`, `\\`, and `\"` escapes. Unquoted inline comments require whitespace before `#`; a leading `#` with no separating whitespace is literal. No interpolation or shell execution occurs. Duplicate or case-colliding keys, malformed lines, and multiline quotes are rejected without printing values. The entire batch is validated and encrypted before publication. `--replace` permits existing names while preserving their recipients; `--recipient` applies only to new entries.

Secret values are limited to 1 MiB, encrypted documents to 4 MiB, recipient records to 64 KiB/100 recipients, and vaults to 1,000 secrets and 128 MiB of managed files. Encrypted snapshots are cached; `--offline` reads only available cached files and reports the revision and last check time. Online failures never silently fall back to stale data.

Derived identities use mode-0600 files inside private temporary runtime directories because SOPS may reopen the identity for each recipient. Normal completion, errors, and handled termination remove them. A forced kill or host crash can leave a temporary file behind; the source SSH key’s passphrase does not protect such a leftover derived identity. No derived identity is written to configuration, Git, the Nix store, or the persistent cache.

Exit codes are `0` for a completed operation, `1` for operational failure, `2` for invalid input/configuration, and `3` for partial listings. Successful removal still prints its security warning. Machine-readable listings use `--json`; secret values are emitted only by `get`.
