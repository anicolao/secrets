# Vision

## Purpose

Make small-scale secret sharing feel like publishing and reading ordinary Git repositories. A person should be able to name a secret, choose who can decrypt it, and publish it without operating a secrets service. A recipient should be able to find things shared with their key without keeping a separate invitation link for every vault.

The building blocks have distinct jobs: Nix distributes a reproducible command environment; SOPS stores encrypted values; age supplies encryption recipients and local identities; Git records changes; GitHub hosts repositories and provides discovery. This project supplies the conventions and workflow connecting them.

The intended audience is individuals and small technical teams already comfortable with GitHub and already holding an Ed25519 SSH private key. The project prioritizes an understandable file format and a small command surface over enterprise administration.

## The experience we want

### Put a secret somewhere predictable

After selecting a default vault, `nix run . -- add NAME` should be enough. Values enter through a hidden prompt, stdin, a file, or a named environment variable. Literal secret values in positional arguments or flags remain unsupported. The application obtains the named secret’s recipient policy (or defaults a new secret to the user), encrypts the value, publishes the change, and reports the destination and commit. Routine use should not require manually editing SOPS configuration or remembering Git staging commands.

The command must make failure understandable. A rejected push means the change is unpublished. Missing keys mean the client cannot verify the affected secret. An existing name requires an explicit replacement choice. The application must never select a different destination merely because another repository appears in search.

### Import from existing workflows

Environment variables and `.env` files are supported input sources from the first version. Users should be able to import values already supplied by their development tools or automation without copying them into command-line arguments.

`nix run . -- add API_TOKEN --from-env SERVICE_API_TOKEN` reads the existing variable inside the application. Only its name appears in the arguments; users must not expand the variable into a value argument. An unset variable is an error, distinct from an explicitly empty value. Environment-derived values must not appear in diagnostics or be forwarded unnecessarily to child processes. Environment input is a useful integration mechanism, with the same need for careful handling as other plaintext inputs.

Storing an entire `.env` file as one secret through `--file PATH` and importing its entries as separate named secrets are distinct, explicit operations. Entry import parses the file as data: it never sources shell code, executes command substitutions, or implicitly expands references using the process environment. The supported syntax must be documented, and malformed or duplicate entries must fail clearly without echoing values.

An entry import identifies the destination vault, selected entry names, and intended recipients before publishing. Each new secret receives an explicit recipient list; any audience selected for the batch applies only to those new secrets and creates no vault-wide grant. Existing secrets require explicit replacement and retain their own recipient lists. Validate the whole import before publishing so a failure cannot silently leave a partially imported batch. Importing values does not establish that they were freshly generated or clear removal warnings.

### Share through a public key

Alice obtains Bob’s SSH-derived or native public age recipient through a channel she trusts and adds it to a particular secret. The application makes that secret readable by Bob and preserves its recipient list on replacement. Adding a different secret starts with its own explicit audience. Bob's GitHub username is useful context, but the public key is the encryption address.

For a public vault, Bob does not need a GitHub repository invitation to fetch ciphertext. For a private vault, Alice also arranges GitHub read access. Encryption access and hosting access are separate requirements. Giving Bob an age recipient entry never implicitly gives him GitHub write permission.

Per-secret recipients are fundamental from the first version. Alice can keep a personal password, a credential shared with Bob, and a credential shared with Carol in the same vault. Each secret names its complete audience. There is no inherited vault-wide grant, and no recipient automatically receives other secrets in that repository. GitHub write permissions remain repository-wide; they are separate from decryption rights.

### Find what has been shared

Bob asks for `secrets list`; the application searches GitHub for his complete age recipient in small per-secret recipient records, then verifies and decrypts matching secrets. `vaults list` groups those matches by repository. Bob can also paste the age address from `identity show` into GitHub code search to locate the same records. Search is the entry point; inspection and decryption supply the evidence.

The experience should distinguish an empty vault, an inaccessible repository, a corrupt file, and an incomplete search. Absence from search is never evidence that no vault exists. Direct repository registration supports private teams, new vaults, and any repository that search misses.

### Move between machines without changing the model

On another machine, Bob installs Nix, authenticates to GitHub, and restores his identity from his own backup. His default Ed25519 SSH key supplies the identity automatically; other key paths and native age identities can be registered explicitly. He discovers secrets or explicitly registers vaults. He does not need a project-operated account or database export.

Local defaults and registrations are conveniences. The repositories and identities are the durable assets. Multiple registered identity files allow a transition between old and new keys, while one selected recipient is included when creating a secret. No key is needed merely to define an empty repository container.

## Product principles

### Reuse the user’s SSH identity

The default is the existing Ed25519 SSH key at `~/.ssh/id_ed25519`. Derive a stable native age address for sharing and search, and derive its private counterpart only while decrypting. A separate age key should not be a prerequisite. An explicit identity selection supports other file locations and native age keys. Unsupported SSH types must fail clearly rather than silently selecting or generating a different identity.

The SSH key and its derived age identity share a lifecycle: changing SSH login authorization does not revoke decryption, and deleting the old private key can lose access to historical secrets. Key migration must update each relevant secret, with no implicit vault-wide grant.

### Keep the format usable without this application

A vault should remain an ordinary repository of standard SOPS files. A technically capable user can inspect the public policy, clone the repository, and recover values with existing tools. Document the small inner payload schema, including its byte encoding. Avoid a proprietary encrypted container or mandatory online service.

### Make the recipient policy explicit

Each secret has a small `recipients.json` containing complete public age recipient strings. These are its sharing policy and searchable addresses. The application checks that the paired ciphertext’s recipients agree with that record before publishing either. Keeping the record separate allows discovery even for larger encrypted values. The root vault manifest only identifies the format.

A recipient record cannot itself force access restrictions: ciphertext determines what can be decrypted, and a writer could use other tools to violate the convention. The application therefore validates policy consistency and treats decryption success separately from policy declarations. Repository write access is a position of trust.

### Keep Nix out of the secret lifecycle

Nix packages the application and dependencies. Runtime code reads private keys and secret values from local inputs. No secret becomes a flake argument, derivation input, build output, or generated Nix expression. Reproducible distribution should not turn private data into a build artifact.

The application flake is distinct from vault repositories. A discovered repository is never an instruction to evaluate its flake, run its scripts, or load arbitrary extensions.

### Be honest about what public discovery reveals

Searchability requires publishing an address someone can search. In a public vault this exposes participation and allows repositories using the same key to be correlated. Secret names, history, timings, and ciphertext sizes also reveal information. Encryption of values does not erase that metadata.

Private repositories reduce public exposure but constrain discovery and retrieval to GitHub-authorized accounts. The proposed default is private creation, with `--public` making the broader discovery model a deliberate choice. This is a product default, not a claim that private hosting replaces encryption.

### Make retained knowledge visible

Removing someone from a recipient list is not a security reset. They may have copied the value, and old Git revisions remain decryptable. The removal command must always explain that it changes encryption access without changing the secret or revoking a live credential.

Track when the actual value was generated separately from when it was stored, re-encrypted, or someone was removed. Preserve each removal event and its value generation in encrypted per-secret metadata. Generation time for imported values is unknown unless the writer explicitly supplies it; an encryption timestamp must never stand in for it.

The UI should continue saying that a former recipient may know the current value until a fresh replacement after removal is reported. Saving identical bytes cannot clear the warning. A replacement with unknown provenance remains uncertain, and a later removal makes regeneration relevant again. A reported fresh replacement is useful evidence, not proof of safety: the application cannot verify copied data was erased or that an old service credential was invalidated. Show these distinctions in secret listings and retrieval warnings, including machine-readable output, rather than leaving them only in documentation.

### Prefer explicit recovery over invisible state

Report whether a change reached GitHub. Keep interrupted encrypted work recoverable. Refuse to overwrite concurrent changes or silently merge recipient policies. Local caches may accelerate reads but must identify stale data. A user should always be able to identify the repository and revision that supplied a value.

## Trust and limits

The trusted computing base includes the local machine, the application and packaged tools, private key storage, and the people allowed to write a vault. GitHub controls availability, repository access, search, and the revisions served. Git history helps users inspect changes but is not automatically a tamper-proof audit log.

Successful decryption establishes that the local key can read valid encrypted data. It does not authenticate a particular sender: anyone with a public recipient can create ciphertext for it. A malicious repository can advertise someone's key and offer misleading content. Users must recognize repository provenance before relying on its values; the client must not execute or automatically inject discovered secrets into other programs.

The project cannot revoke knowledge. Removing a recipient restricts subsequent encryption, but previous versions and copies remain. Revoking a live password or token requires changing it with the service that honors it. Similarly, deleting a file is not secure erasure of Git history.

There is no recovery authority. A person who loses all authorized private keys loses access to the encrypted values. Teams may include an independently backed-up recovery recipient, only on the secrets it should be able to recover. There is no implicit recovery access to the rest of a vault.

## Initial scope and deliberate exclusions

The first useful version provides vault creation, local defaults, secret addition and replacement, environment-variable input, `.env` entry import, retrieval, recipient changes, explicit registration, and discovery-backed listings. It supports GitHub.com, per-secret recipient lists, and native classic age recipients derived by default from `~/.ssh/id_ed25519`, with interoperable SOPS files and no service to deploy. Native age identity files remain an explicit alternative.

It excludes key escrow, hardware integrations, browser extensions, dynamic credentials, scheduled rotation, deployment injection, GitHub organization administration, and pull-request publication workflows. These features introduce separate policy or operational concerns. The initial implementation should establish reliable storage and retrieval first.

Possible later work includes stronger publisher verification, richer key migration, other Git hosts, hardware-backed identities, and integrations that consume secrets at runtime. None should make existing vaults depend on a hosted control plane or obscure the recipient policy. New recipient types require an explicit format and compatibility review.

## What success looks like

- A new user can create a vault, add a value, and read it back without manually editing encryption configuration.
- Users can import existing environment variables and `.env` entries without putting values in command-line arguments, executing file contents, or unintentionally changing existing secrets’ recipients.
- A second user can discover individual public secrets by searching their age recipient, without receiving a repository URL, and decrypt exactly the secrets addressed to them.
- Two secrets in one vault can have different audiences; changing one secret’s recipients never changes the other’s accessibility.
- The default SSH identity works without generating or permanently storing a separate private key.
- The same workflow works for private vaults when repository access is granted, with explicit registration available whenever discovery misses them.
- A person without an authorized identity cannot decrypt test secrets even with the complete repository history.
- Recipient changes leave a consistent current vault, and failures never publish a partially changed policy.
- Removal always warns that existing copies remain usable; listings distinguish value generation from removal and retain unresolved warnings across re-encryption, unchanged replacements, and repeated removals.
- Users can explain where their private key lives, what metadata is visible, and why removing a recipient cannot retract old secrets.
- A vault remains recoverable with Git, SOPS, and the documented payload schema if this application is unavailable.

The [MVP design](MVP_DESIGN.md) turns these goals into an implementable first version. This document describes intent; no implementation is included at this stage.
