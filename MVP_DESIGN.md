# MVP design

## Status and decisions

This document describes the implemented MVP contract and its verification criteria. See [the README](README.md) for operation and recovery and [the vision](VISION.md) for product intent.

| Area | MVP decision |
| --- | --- |
| Distribution | One Nix flake exposing a default command named `secrets` |
| Hosting | One GitHub.com repository per vault |
| Creation | Private by default; explicit `--public` |
| Authorization unit | Independent explicit recipient set for each secret |
| Key types | Native age X25519 recipients, derived by default from the existing Ed25519 SSH key |
| Storage | One searchable recipient record and one SOPS JSON document per secret |
| Discovery | Search full age recipients in per-secret records; supplement with known vaults |
| Verification | Current manifest validation followed by actual decryption |
| Removal status | Track value generations separately from recipient removals; never equate removal with revocation |
| Publishing | GitHub Git database objects and a non-force branch-reference update |
| Implementation | Small Python CLI orchestrating packaged `sops`, `age`, `ssh-to-age`, OpenSSH tools, `git`, and `gh` |
| Platforms | Initial targets: `aarch64-darwin`, `x86_64-darwin`, `aarch64-linux`, `x86_64-linux` |

The default identity source is `~/.ssh/id_ed25519`; derive a native age recipient and identity with pinned `ssh-to-age`. Explicit native age identity files are also supported. Native identity files containing multiple keys require `identity default` to select self; do not silently choose a key from an ambiguous source. This format uses native `age1…` recipients consistently, not direct SSH recipient stanzas. RSA, ECDSA, hardware/agent-only SSH keys, other age types, plugins, and threshold groups are outside version 1. Validate conversion and SOPS interoperability against pinned versions before release.

## Command contract

All examples use `nix run . -- …` from the application repository. The arguments after `--` reach the packaged CLI through the flake's default app; see the [Nix run reference](https://nix.dev/manual/nix/stable/command-ref/new-cli/nix3-run).

| Command | Meaning |
| --- | --- |
| `identity add PATH --type TYPE` | Register an alternate identity source; first registration overrides the implicit SSH default |
| `identity show` | Display derived public recipients and the selected self recipient, never private key text |
| `identity default RECIPIENT` | Select the self recipient included in newly created secrets |
| `create VAULT_NAME [--owner OWNER] [--public\|--private]` | Create and initialize a new GitHub repository; owner defaults to the authenticated user |
| `vaults add OWNER/REPO` | Validate and register a known vault without depending on search |
| `vaults default OWNER/REPO` | Set a registered, fetchable vault as the default for unqualified operations |
| `vaults list [--offline] [--json]` | Refresh discovery and report matching vaults, or explicitly use cached snapshots |
| `add NAME [--stdin\|--file PATH\|--from-env VARIABLE_NAME] [--recipient RECIPIENT]... [--replace] [--generated-at TIMESTAMP] [--vault OWNER/REPO]` | Encrypt and publish a new value; replacing an existing name requires `--replace` |
| `import-env PATH [--key NAME]... [--recipient RECIPIENT]... [--replace] [--generated-at TIMESTAMP] [--vault OWNER/REPO]` | Atomically import selected dotenv entries; replacement preserves existing audiences |
| `get NAME [--vault OWNER/REPO] [--offline]` | Verify and emit the exact value bytes to stdout |
| `secrets list [--vault OWNER/REPO] [--offline] [--json]` | List verified readable names without values |
| `recipients list NAME [--vault OWNER/REPO]` | Show the named secret’s public recipient set |
| `recipients add NAME RECIPIENT [--vault OWNER/REPO]` | Grant access to this secret and its subsequent replacements |
| `recipients remove NAME RECIPIENT [--vault OWNER/REPO]` | Remove a recipient from current encryption, record the event, rotate the data key, and warn that copies remain usable |

These are the complete required commands for version 1. Deleting secrets, renaming them, and automatic private-key generation can follow later. The existing default SSH key is used without registration; no key is generated silently. Identity registration accepts `--type ssh-ed25519` or `--type age`.

For `add`, `--stdin`, `--file`, and `--from-env` are mutually exclusive. With neither, prompt on a terminal with echo disabled; fail on a noninteractive invocation rather than hang. Prompted values are UTF-8 text. File and stdin input are arbitrary bytes, including empty values and trailing newlines. There is no positional value or `--value` option. `--from-env VARIABLE_NAME` reads an existing variable within the process; unset is an error and empty is a valid value. Remove this variable from child-process environments. Reject extra arguments before any mutation or network call, and never include rejected tokens in errors, telemetry, or debug logs. Parser failures must use generic messages because the extra argument may be a secret. The application cannot erase an argument from the invoking shell’s history, so documentation must not teach that input pattern. Stdin examples use file redirection or a producer, never shell literals containing secret values.

For a new secret, the audience is the selected self recipient plus every repeated `--recipient`. Every stored list is explicit and independent; there are no vault defaults or inherited grants. `--replace` preserves the existing recipient list and rejects `--recipient`; recipient changes use the dedicated commands. Replacements and recipient changes require the ability to decrypt that secret, not the other secrets in its vault. The wrapper never passes values or private keys to child processes through arguments or environment variables.

`import-env` parses UTF-8 data without shell evaluation or variable expansion. Version 1 accepts blank lines, comments, optional `export`, and single-line unquoted, single-quoted, or double-quoted values. Double quotes support explicit newline/tab/backslash/quote escapes. Reject duplicate keys, malformed entries, and multiline quoted values with line-number-only diagnostics. Repeated `--key` selects entries; omission imports all. New entries receive self plus explicit recipients, while existing entries require `--replace` and preserve their audience. Validate and encrypt the whole batch before a single commit. Imported values have unknown generation time unless asserted with `--generated-at`.

Unqualified writes, reads, and recipient commands use the local default. `--vault` always wins. `secrets list` without `--vault` spans discovered and registered matching vaults; it is deliberately broader than the write default. No default means an unqualified operation fails with setup guidance. Search never changes the default.

The first successfully published vault becomes the default if none exists. Later creations leave it unchanged. Any registered, fetchable vault, including an empty vault, is eligible as a default. GitHub write permission is checked when publishing; readability of unrelated secrets is not a prerequisite.

`get` adds no newline and writes diagnostics only to stderr. Lists show repository, secret name where applicable, revision, verification status, and the separate value/removal status specified below. JSON output has a versioned object containing `items`, `errors`, `partial`, and `discovery_complete: false`; the latter avoids implying a global GitHub inventory. Exit codes: `0` for completed requested work, `1` for an operational failure, `2` for invalid usage/configuration, and `3` for a listing with partial results. Intrinsic search incompleteness is always documented; detected truncation, rate limiting, or vault failures set `partial` and exit `3`.

## Vault format

The repository's current default branch is the authoritative published snapshot. New repositories start with `main`. Identify vaults by GitHub's numeric repository ID plus the current `OWNER/REPO` name; copied manifests in forks are different vaults. Do not trust a manifest to redirect retrieval elsewhere.

```text
vault.json
secrets/
  API_TOKEN/
    recipients.json
    value.sops.json
  OTHER_TOKEN/
    recipients.json
    value.sops.json
README.md
```

### Vault marker and per-secret policy

The root `vault.json` contains only `{"format":"github-sops-vault","version":1}`. It identifies a container, with no recipients or access inheritance.

Each `secrets/<NAME>/recipients.json` is the public policy and discovery record for its sibling `value.sops.json`:

```json
{
  "format": "github-sops-secret",
  "version": 1,
  "name": "API_TOKEN",
  "recipients": [
    "<complete native age recipient derived from Alice's SSH key>",
    "<complete native age recipient for Bob>"
  ]
}
```

The strings above are schematic placeholders. Real records contain canonical full `age1…` strings, one per line. Reject unknown fields, duplicate JSON keys, duplicate recipients, empty sets, unsupported versions, malformed keys, private identity material, and disagreement between `name` and directory. Sort recipients when writing. Limit each record to 64 KiB and 100 recipients. The root marker is also limited to 64 KiB. No record may redirect a client to another path or repository.

Each secret uses its own fresh SOPS data key. Its ciphertext recipient metadata must exactly match its sibling record. Do not share data keys between secrets, even if their audiences happen to match. This separation allows different audiences in one vault and makes changing one secret independent of every other secret.

There is no committed `.sops.yaml` in version 1. The wrapper supplies explicit per-secret recipients with an empty SOPS configuration. Every mutation performs fresh encryption with a new data key, including recipient additions and removals. Ignore ambient SOPS recipient settings and inherited configuration. Reject non-age backends, threshold groups, and unencrypted payload exceptions. Recipient records are policy declarations, not proof of access or publisher authenticity; verify the paired ciphertext before reporting a readable secret.

### Secret names and values

Names match `[A-Za-z][A-Za-z0-9_-]{0,63}`. Reject path separators, traversal, and case-insensitive collisions so vaults behave consistently on common macOS and Linux filesystems. Names are public metadata.

Before SOPS encryption, each file has this logical JSON shape:

```json
{
  "schema": 1,
  "name": "API_TOKEN",
  "encoding": "base64",
  "value": "ZXhhbXBsZQ==",
  "lifecycle": {
    "sequence": 1,
    "generation": {
      "id": "<random generation UUID>",
      "introduced_sequence": 1,
      "recorded_at": "2026-09-23T17:00:00Z",
      "generated_at": null,
      "generation_evidence": "unknown"
    },
    "removals": []
  }
}
```

All nonempty payload values, including lifecycle fields, are encrypted. Standard SOPS output leaves nulls, empty strings, and empty containers structurally visible; the schema validates those after decryption. After decryption, validate the schema, encoding, and agreement between `name`, its directory, and its public recipient record before decoding `value`. Base64 preserves arbitrary bytes; it provides no secrecy on its own. The decrypted payload must never be written into the repository. Limit decoded values to 1 MiB, encrypted documents to 4 MiB, and vaults to 1,000 secret directories and 128 MiB of managed files for the MVP. Fail explicitly on oversized input.

Use standard SOPS output and metadata, preserving its integrity checks. SOPS protects a file's data key for the configured age recipients, allowing each corresponding identity to decrypt the same document. See [SOPS age support](https://getsops.io/docs/usage/identities/age/). The format does not duplicate the whole secret once per person.

## Local configuration and key handling

Use `$XDG_CONFIG_HOME/secrets/config.json` (fallback `~/.config/secrets/config.json`) for identity file paths, the selected self recipient, default vault, and explicitly registered repositories. Store public metadata and encrypted snapshots under `$XDG_CACHE_HOME/secrets` (fallback `~/.cache/secrets`). Pending encrypted transactions belong under `$XDG_STATE_HOME/secrets` (fallback `~/.local/state/secrets`) so cache cleanup cannot silently discard unpublished work.

Create application directories with mode `0700` and configuration/state files with mode `0600`. Identity registration records an absolute path and public recipients; it does not copy the key into configuration. Reject group/world-readable private key files and explain how to fix their permissions. Backups remain the user's responsibility.

Identity resolution is deterministic: explicit registered configuration takes precedence; with none, use only `~/.ssh/id_ed25519`. Do not scan other keys or silently fall back to RSA. A missing default key gives setup guidance. Support multiple explicitly registered sources and query all their derived public recipients; select one as self for new secrets.

Use [ssh-to-age](https://github.com/Mic92/ssh-to-age) to derive native age keys from Ed25519 SSH material. Its public conversion allows a stable `age1…` address; private conversion supports encrypted SSH keys with passphrase input via stdin. The client prompts privately when unlocking is required and passes the passphrase through a dedicated pipe, never an argument or environment variable. Unsupported key encryption formats produce an actionable error; the application never rewrites the SSH key.

Derive public material from the private key when establishing a source, checking any `.pub` file against it. Verify the public/private binding on each invocation; do not trust an unrelated `.pub` file. The current implementation unlocks identities before searching and does not persist derived public-key caches. Identity selection changes never automatically rekey existing secrets.

Derived private identities exist only during the invocation. Provide selected identities through an exclusively created mode-0600 file in a private temporary directory outside repositories and caches. SOPS reopens this seekable file for different recipients. Delete it on normal completion, failures, and handled termination; a forced kill or host crash may leave it behind. It must never become a persistent exported age key. Clear ambient SOPS key sources and key-command hooks. This design does not depend on SOPS directly unlocking an SSH key or on `ssh-agent` access.

Key replacement requires adding the new age recipient to each affected secret and then removing the old one. Removing an SSH key from GitHub login authorization does not revoke decryption. Retain old key backups when historical values must remain recoverable.

Use the existing GitHub CLI credential setup; do not store GitHub tokens in vaults or application configuration. Authentication scopes and repository permissions must suffice for the requested operation. Read access, write access, and repository creation are distinct capabilities; organization policy can deny creation or direct pushes.

## Creating and publishing vaults

1. Validate the name, authentication, and destination owner. Do not adopt an existing repository under `create`.
2. Prepare the root format marker and explanatory README in memory. It contains no secrets or private keys.
3. Create the GitHub repository with the requested visibility and an initial README commit, then publish the vault marker and explanatory README via the Git database API.
4. Register its repository ID/name and choose it as default only after publication succeeds.
5. Print its URL, visibility, and commit. If creation succeeds but publication fails, report the empty remote and recovery information; do not delete it automatically or claim success.

A vault is usable before it has secrets. It has no addressed secrets yet and cannot be discovered by recipient search. A registered empty vault appears as `known-empty`, separate from vaults containing matches.

## Secret write transaction

1. Resolve the explicit/default vault and take a local per-repository lock. Refuse to start while an unresolved transaction exists.
2. Fetch the current default-branch revision and bounded Git tree/blob data through GitHub APIs without a checkout. Validate the root marker, safe paths, and the target secret’s recipient record and ciphertext. For replacements, decrypt and validate the target. Never require decryption of unrelated secrets; their different audiences are expected.
3. Record the base commit and target policy digest (or target absence for creation). Validate the secret name and replacement rule before asking for a value.
4. Read the value, construct its inner payload in memory, and feed it to SOPS through stdin using the target’s explicit recipient list. Create a new data key for each new secret. Update the encrypted lifecycle metadata according to the generation rules below in the same transaction. Capture only encrypted output on disk.
5. Decrypt the new document into memory, validate its payload, and compare the recovered bytes with the input. Reject any mismatch or failed integrity check.
6. Upload only the target’s ciphertext and recipient record as Git blobs; build a tree against the fetched base tree and a single commit with that base as its parent. Use a generic commit message without a secret value.
7. Update the recorded branch reference through GitHub with `force: false`. A divergent concurrent update must cause rejection; never force an update, automatically merge encrypted JSON, or silently replay a write under a changed recipient policy.
8. Report success only after confirming the remote revision. Before creating remote objects, save ciphertext and the base revision as pending local state; record the proposed commit before updating the reference. On failure retain this state, report its location and a manual recovery path, and exit nonzero. Retrying requires refreshing and reviewing the remote state. Plaintext is not retained for retry.

If a network failure makes the push outcome ambiguous, fetch the remote to determine whether the commit landed. If that check also fails, report an unknown publication state. Branch protection failures are normal operational failures; PR-based writes are out of scope.

Remote repositories are untrusted data. Read only Git API tree/blob data, never a working checkout; hooks, external filters, submodules, and LFS downloads are not invoked. Reject symlinks and unexpected file types in managed paths. Use argument arrays without a shell, constrain remotes to the intended GitHub host/repository, and bound reads before parsing. Reading a vault must not execute files from it.

## Recipient changes

Every recipient command takes a secret name. Listing recipients reads public policy and requires only repository read access. Adding or removing recipients requires an acting identity that decrypts that secret and GitHub write permission. Show its old and proposed recipient sets. Refuse removal of the final recipient and removal of the acting recipient in the MVP; a different authorized writer can complete that person’s removal. These restrictions apply only to the target secret.

For additions and removals, update the target’s recipient record and freshly encrypt its unchanged value and updated lifecycle using only the resulting recipients. This creates a fresh SOPS data key on every mutation, avoiding reuse of a key known to a removed recipient. The generation of the secret value remains unchanged. This is a simpler equivalent to updating recipient wrapping and rotating the data key; see [SOPS key management](https://getsops.io/docs/usage/key-management/). No other secret is processed.

On removal, append the encrypted removal event described below before verifying the target. Verify exact agreement of the record and ciphertext and confirm the secret value bytes and generation metadata are unchanged; lifecycle removal metadata is the intended payload change. Commit and push the pair together. On failure publish neither. Other secrets remain byte-for-byte unchanged, and inability to decrypt them is expected rather than an error. A mismatch on the target blocks the operation and is reported without silently repairing its policy.

Removal does not invalidate old ciphertext, copied plaintext, or unchanged live credentials. A removed reader can retain the old value from history. After removing a compromised identity, rotate the actual service credential and publish its replacement; encryption-key rotation alone does not change the service's password or token.

## Value generation, removal history, and UI warnings

Removal is not revocation of the secret value. The UI must distinguish three events: replacing the actual value, removing an encryption recipient, and rotating a SOPS data key. Only a genuinely new value can stop a former recipient from knowing the current value, and only the credential issuer can invalidate an old live credential. Neither timestamp comparisons nor the application can prove that copies were destroyed or external revocation occurred.

### Encrypted lifecycle metadata

Store lifecycle metadata inside `value.sops.json`, protected by SOPS integrity verification. Keep it out of `recipients.json`: that public record contains only current recipients and discovery metadata. This avoids creating current search hits solely because someone was removed, while authorized readers can still inspect removal history. Historical Git revisions may continue exposing previous recipient lists.

- `sequence` is a positive per-secret operation counter. Increment it for each published value or recipient change. Concurrent writes use the existing base-commit/push checks; never merge counters from divergent histories automatically.
- `generation.id` is a random UUID identifying the recorded value version, never a hash of plaintext. `introduced_sequence` records when that version entered the vault; `recorded_at` is the UTC time it was stored. These are distinct from when it was generated externally.
- `generation.generated_at` is a nullable UTC RFC 3339 timestamp of actual value generation, explicitly reported by the writer. `generation_evidence` is `unknown` or `user-asserted`. The MVP imports values; it does not invent a generation time based on a write, commit, or encryption timestamp.
- Each entry in `removals` contains `event_id` (random UUID), `recipient` (complete public age recipient), `removed_at` (UTC RFC 3339), `sequence`, and `generation_id_at_removal`. Record every successful removal, including repeated removals after re-addition. Retain prior entries through replacements and recipient changes; do not silently truncate them. Existing encrypted-document size limits apply, with an explicit failure if exceeded.

These records are writer-maintained evidence, not a trusted clock or immutable audit log. Validate structure, unique IDs, counter ordering, and generation/removal references where available. Missing or inconsistent lifecycle data produces `unknown` status, never an assertion that the value is safe. Basic decryption may remain usable with a prominent metadata warning, but lifecycle-changing writes require repair from verified history; do not silently initialize away an existing secret’s removals. Git history can aid repair but is not required on every normal read and cannot prove completeness after a rewrite.

### Recording a generation

`add NAME` creates a generation ID with an unknown actual generation time by default. A successful `add NAME --replace` compares decoded bytes privately with the current value. Different bytes create a new generation ID and record when they were stored, while preserving all removal events. Different bytes alone do not demonstrate newly generated material: a user could paste an old credential.

`--generated-at TIMESTAMP` explicitly asserts when the supplied value was freshly generated. It is metadata, never a secret input channel. Accept it on initial creation or a replacement with different bytes; reject an identical-value replacement carrying this flag so metadata cannot launder unchanged material into a new generation. Without it, an identical-value replacement is a no-op that preserves generation information and any warnings. Reject invalid or future generation times relative to the transaction’s recording time. The timestamp cannot verify the user’s assertion, value unpredictability, historical reuse, or external service state.

Changing recipients, rotating an encryption key, or re-encrypting the same bytes never changes the generation ID or generation time. Adding a removed recipient back does not erase removal history or constitute regeneration. A later removal creates a new event and again requires consideration of the value that person could know.

### Determining and presenting status

Evaluate the current generation against **every** recorded removal, using operation sequence as the causal ordering and timestamps as reported generation evidence. Equal timestamps are insufficient; a value generated before removal but stored afterward is insufficient. Clock anomalies or incomplete evidence remain unresolved.

| Status | Condition | User-facing meaning |
| --- | --- | --- |
| `no-removals-recorded` | Valid lifecycle with no removal entries | No recipient removals are recorded; this is not a claim of secrecy |
| `rotation-needed` | A removal occurred at or after the current generation’s introduction, or a reported generation time is at/before a removal | A former recipient may still know the current value; generate a replacement and invalidate old credentials where applicable |
| `unknown` | Lifecycle evidence is missing/inconsistent, or a later replacement lacks a reported generation time establishing freshness after every removal | A replacement or timestamp is insufficient to establish freshness; former-recipient knowledge remains possible |
| `replacement-recorded` | Current generation was introduced after every removal and its user-asserted generation time is strictly later than every removal time | A fresh replacement after all recorded removals has been reported; external revocation and absence of copies are unverified |

For a history with mixed evidence, any known unresolved removal yields `rotation-needed`; otherwise any uncertainty yields `unknown`. Provide the unresolved event IDs and last removal time as well as the current generation’s reported generation and recording times. Never label `replacement-recorded` as “secure,” “revoked,” or “recipient no longer knows the secret.” Even a fresh replacement cannot invalidate the old service credential by itself, and history cannot account for disclosure outside the vault.

`secrets list` displays this status alongside readability and dates. JSON secret rows include `generation`, `last_removed_at`, `removal_status`, and `unresolved_removal_event_ids` without values. `vaults list` aggregates unresolved/unknown counts among readable matching secrets and does not interpret unreadable secrets as resolved. `get` emits any unresolved-removal warning to stderr and preserves exact value bytes on stdout. `recipients list` reports current encryption policy; without decryption it labels lifecycle status `unknown`, never guesses from public metadata.

### Required removal warning

Before an actual removal, always write this warning to stderr, including in noninteractive mode:

> Removing a recipient does not revoke the secret. They may retain plaintext or decrypt old Git revisions. This operation changes current encryption recipients and the encryption key; it does not change the secret value or invalidate a live credential. Generate a fresh replacement after removal and revoke the old credential at its issuer where applicable.

After successful publication, report the recipient and removal time, the value generation time (or “unknown”), and `rotation-needed`: “Recipient removed from current encryption; existing copies may still work.” Print the repository revision so the event can be inspected. A successful removal uses exit `0` for publication success, with the warning still visible; the status is not a claim of security. No extra confirmation or acknowledgment flag is required, and ordinary quiet output must not suppress this warning. A failed or uncertain push must not claim the removal event is published.

For example: a value reported generated at 09:00 and a recipient removed at 10:00 remains `rotation-needed` after re-encryption at 10:01. Recording identical bytes at 11:00 cannot clear that state. A different value stored at 11:00 without generation evidence is `unknown`; one reported freshly generated at 10:30 can be `replacement-recorded`. A second removal at 12:00 returns the state to `rotation-needed`. All times refer to the same date in UTC, and every transition must be published atomically with its metadata.

## Discovery algorithm

The implementation uses authenticated GitHub REST code search through `gh api`. Its query is conceptually:

```text
<complete-public-age-recipient> in:file filename:recipients.json
```

URL-encode the query through API parameters; do not interpolate it into a shell command. The exact supported query and indexing behavior must be exercised against GitHub before release, rather than inferred from the web search interface.

1. Resolve the default SSH identity or explicit sources and derive/deduplicate their native age recipients. `identity show` exposes these public addresses for manual GitHub searches too.
2. Search separately for each complete age recipient in `recipients.json`, following pagination and rate-limit headers. Search is automatic; users need not know repository URLs. Retain diagnostics for incomplete or capped searches.
3. Merge hits with recipient records enumerated from explicitly registered, previously discovered, and newly created vaults. Inspect only bounded paths matching `secrets/<NAME>/recipients.json`.
4. Deduplicate by repository ID and secret path, not merely by repository. Fetch each repository’s current default-branch commit, then its root marker, recipient records, and target ciphertext at that same revision. Do not rely on search snippets or older indexed policy.
5. Validate each record and exact membership of a local recipient. A secret addressed only to others is excluded normally, not reported as a decryption failure. Reject malformed candidates; report failures in known vaults and diagnostics for rejected search hits.
6. For matching secrets, require exact policy/ciphertext agreement, successful SOPS integrity verification, and a valid inner payload. Evaluate encrypted lifecycle evidence, discard decrypted values, and list verified names qualified by repository with their separate removal status. Missing lifecycle evidence must remain visible as unknown rather than hiding a readable secret. Claimed-but-unreadable secrets appear in diagnostics, never as readable values.
7. `vaults list` groups addressed matches by repository and reports counts of verified and failed secrets, using `verified-readable`, `partial`, or `unreadable`. Registered vaults with no matching records appear separately as `known-no-matches` or `known-empty`. Empty repositories cannot count as secrets addressed to the user.
8. Cache repository identity, secret path, commit, check time, and nonsecret statuses, never plaintext. Sort by repository then secret name. Known vaults remain registered through temporary access failures. A corrupt addressed secret does not hide other successes.

The API limits searchable files to less than 384 KB, searches only the default branch, caps results at 1,000 per query, and may report incomplete results. Search scope and repository permissions also limit coverage. Keep per-secret discovery records small regardless of ciphertext size, support direct registration, and expose these limitations. See [GitHub REST search](https://docs.github.com/en/rest/search/search#search-code).

Inaccessible private repositories cannot be discovered merely by owning a decryption identity. Search results may be stale or absent, and someone can intentionally publish another person's recipient. A candidate is neither proof of access nor proof of publisher identity. The client only reads data and does not consume discovered values automatically.

By default, reads refresh the remote. `--offline` is an explicit choice to use cached encrypted snapshots, with commit and cache age shown in diagnostics/list output. Verify decryption again locally. Missing snapshots or failures are errors; an online failure never silently falls back to stale data. A cached older revision may retain access after removal, which is an inherent historical-access limitation.

## Nix packaging and implementation structure

The flake pins `nixpkgs` in `flake.lock`, exposes `packages.<system>.default` and `apps.<system>.default`, and offers a development shell and checks. Package the Python entry point with fixed paths to the required runtime binaries. The app must run from an arbitrary working directory; vault resolution comes from explicit arguments and local configuration.

Separate modules for CLI parsing, local configuration, GitHub discovery, vault schema validation, SOPS execution, and Git transactions keep external tools mockable. Use the standard library for the version-1 JSON schemas. There is no background daemon, remote database, or custom cryptography.

Nix evaluation and builds must never read identities or values. Vaults and runtime state stay outside the application source tree to prevent accidental inclusion in flake source snapshots. Secret processing occurs only after launching the built command. Do not add vaults as flake inputs, derive Nix expressions from secret values, or execute discovered flakes.

## Failure and security behavior

| Condition | Required behavior |
| --- | --- |
| Missing identity or GitHub authentication | Explain the missing setup; do not create substitute keys or return an empty listing |
| Recipient record/ciphertext mismatch | Reject changes to that secret and exclude it from verified-readable results |
| Integrity failure or invalid inner payload | Emit no plaintext; report vault, path, and revision |
| Search rate limit or truncation | Preserve usable results, mark partial, and explain direct registration |
| Concurrent push or policy change | Preserve encrypted pending work; require a fresh explicit attempt |
| Key loss | Explain that another authorized key or backup is needed; no GitHub-based recovery claim |
| Malicious candidate repository | Bound parsing and downloads; execute no supplied content |
| Failure during removal | Publish neither the target’s changed record nor its rotated ciphertext |

Buffer decrypted output until SOPS exits successfully and payload validation completes. `get` is the only command that emits a secret value. Diagnostics, exception traces, subprocess logging, commit messages, and JSON listings must omit plaintext and identity contents. Rejecting value arguments and using hidden input or pipes reduce ordinary exposure but do not protect against a compromised machine, memory inspection, or caller-created plaintext files.

Encryption integrity does not establish author identity or prevent GitHub from serving an older valid revision. The MVP relies on the selected repository and GitHub account controls for provenance; signed publication and rollback detection are future work.

## Acceptance criteria and implementation sequence

Use throwaway keys and fake values in every automated test. The suite exercises real local cryptographic tools and simulated GitHub state; the opt-in live smoke test uses an isolated non-default branch, so default-branch indexing and private-repository access remain separate deployment checks.

1. **Format and local round trip:** validate manifests and names; encrypt/decrypt exact bytes including empty, multiline, binary, and maximum-size inputs. Confirm independent stock SOPS recovery and rejection of a nonrecipient identity.
2. **CLI and packaging:** build on the target systems; exercise automatic SSH identity selection, alternate paths, native age sources, encrypted SSH keys, missing keys, unsupported types, stale `.pub` files, and repeatable public/private conversion. Confirm no persistent derived private key or build-time secret. Reject positional values, value flags, conflicting input modes, and noninteractive prompts without echoing rejected tokens or touching the network.
3. **Publishing:** exercise creation, addition, replacement, failed push recovery, unknown push outcomes, and concurrent writers using disposable repositories or local Git fixtures. Assert that only approved ciphertext/metadata paths are committed.
4. **Per-secret sharing:** place Alice-only, Alice/Bob, and Alice/Carol secrets in one vault. Assert Bob discovers and decrypts only his addressed secret, and can update it with GitHub write permission despite lacking other decryption keys. Add/remove a recipient on one secret; verify other files are unchanged, new-revision exclusion works, and old-revision access persists. Verify that policy and ciphertext publish atomically.
5. **Discovery:** test duplicate results, stale hits, unrelated files, malformed candidates, inaccessible private vaults, pagination, rate limits, and partial success with recorded API fixtures. Exercise explicit registration without search.
6. **Adversarial input:** verify no hook/filter/submodule execution, no traversal or symlink escape, bounded parsing, no plaintext on validation failure, and no secret leakage in diagnostics.
7. **Removal lifecycle:** test distinct generation/recording/removal times, unchanged replacements, imported old values, user-asserted freshness, equal/skewed clocks, missing/tampered metadata, multiple removals, re-addition, and subsequent removal. Verify data-key rotation alone never changes generation metadata or resolves a warning. Test warning output before removal and after publication, including quiet/noninteractive use, and failed or ambiguous pushes. Assert atomic lifecycle/ciphertext updates and that stdout from `get` remains exact.
8. **End-to-end release check:** using disposable GitHub vaults, two identities, and distinct hosting permissions, demonstrate direct search by an SSH-derived age recipient finds the correct individual public secrets across mixed-audience vaults; private retrieval still requires GitHub access. Include a secret whose ciphertext exceeds the code-search size limit but whose recipient record is searchable. Document indexing delays and the pinned tool versions used.

The MVP is complete when users can create a vault, publish and retrieve a secret, share it, discover it from another identity, and understand partial results and revocation limits. The implementation and tests are included in this repository.
