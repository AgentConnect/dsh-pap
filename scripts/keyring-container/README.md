# Isolated real Secret Service verification

This is a module verification harness, not a Host installation or deployment entrypoint.
It imports the packaged real `KeyringSecretStore` and `PapStore`. It contains no fake
`secret-tool` or Secret Service implementation and never imports Agent private keys.

Run from `dsh-pap` after building the private package and installing the fixed dependencies:

```bash
node scripts/keyring-container/run.mjs
```

An optional first argument selects a different absolute evidence root. The default is
`../worktrees/20261104-dsh-shared-agent-identity/.artifacts/keyring-verification/secret-service-container/`.
Each execution creates its own run directory and Docker tag. No image is pushed.

The build uses the digest-pinned Node 22.23.1 Bookworm Slim image. It installs
`libsecret-tools`, `gnome-keyring`, `dbus`, and their dependencies only inside that
image. It copies the private package, the four fixed runtime Node dependencies,
and the three relevant source files. It does not copy environment files or user
configuration. `policy-rc.d` blocks package service startup during image creation.

The actual verification runs as the caller's numeric user with:

- `--rm --network none --read-only`;
- all Linux capabilities removed and `no-new-privileges`;
- finite pids, memory and CPU;
- private finite tmpfs mounts for `/run/task` and `/tmp`;
- one task-owned writable evidence directory.

The verifier creates a DBus config with no activation service directories and private
XDG/runtime/control/state paths. It preserves `HOME`; it does not connect to the
host DBus or keyring. The random keyring password goes only through stdin and memory.

Checks cover real creation/get, encrypted PAP state, recovery in a separate Node
process, gnome-keyring daemon restart, collection locking, recovery by restarting
and unlocking with the stdin password, and deletion of the Secret Service item.
A missing item must make the existing encrypted PAP state fail without recreating
its key or rewriting its ciphertext. The verifier also checks for plaintext key,
password, marker or file fallback in the private regular files.

The lock operation and collection property use the standard
[Secret Service API](https://specifications.freedesktop.org/secret-service/latest/org.freedesktop.Secret.Service.html).
This harness does not require a GUI unlock prompt. Recovery after the explicit lock
uses a fresh task daemon with its stdin password; it does not claim that an in-place
`gnome-keyring-daemon --unlock` invocation worked in this headless environment.

`output/result.json` records checks, actual Debian package versions, source hashes,
limits and cleanup. `runtime.json` records the exact base and built image digest,
input package hash and runtime flags. Runtime output contains no password, secret,
Token, private key or callback material. The image root and packaged source stay
read-only. The test daemon, private DBus and private state are removed before exit;
Docker removes the container.

A passing result is **isolated container Secret Service evidence**. It does not
establish that the host has Secret Service installed or configured, and it does
not replace the earlier real missing-backend Host result.
