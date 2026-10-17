# 🔑 pqp agent as a systemd user service

[pqp](https://github.com/ajdiaz/pqp) can run its passphrase-caching agent
(`pqp agent`) in the background as a **systemd user service**, so `decrypt`,
`sign`, `encrypt --sign` and `edit-key` stop re-prompting for a passphrase.
Cached passphrases live only in process memory and are wiped on expiry,
eviction or shutdown — nothing is ever written to disk.

## Files

| File | Purpose |
|---|---|
| `pqp-agent.service` | systemd *user* unit that runs `pqp agent` in the background |

## Requirements

- `pqp` built with the `agent` command (v0.1.0 or later).
- A systemd user session (`systemctl --user` must work).

## Install

```bash
mkdir -p ~/.config/systemd/user
cp pqp-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pqp-agent.service
```

From a checkout of the repository, `make install-systemd` performs the
`mkdir`/`cp`/`daemon-reload` steps for you.

The unit ships with `ExecStart=/usr/bin/pqp`. If your binary lives elsewhere
(e.g. `~/.cargo/bin/pqp` after `cargo install --path .`, or
`~/.local/bin/pqp`), edit the unit **before** enabling it:

```bash
sed -i "s#/usr/bin/pqp#$HOME/.cargo/bin/pqp#g" \
  ~/.config/systemd/user/pqp-agent.service
systemctl --user daemon-reload
systemctl --user enable --now pqp-agent.service
```

Alternatively, override just the command without touching the packaged unit:

```bash
systemctl --user edit pqp-agent.service
# then add, in the editor:
#   [Service]
#   ExecStart=
#   ExecStart=%h/.cargo/bin/pqp agent --expire-time 1h
```

> **Note:** any `pqp` command resolves the agent socket from
> `--unix-socket-path`, the `[agent] unix-socket-path` config key, or the
> default (`$XDG_RUNTIME_DIR/pqp-agent.sock`, falling back to the pqp data dir
> or `$PQP_HOME/.pqp/agent.sock`). The service and your interactive shell must
> agree on that path — with the defaults they do.

## Verify it works

```bash
systemctl --user status pqp-agent.service   # active (running)
pqp agent --stop                            # sanity: the CLI can reach the socket
systemctl --user start pqp-agent.service    # (managed by systemd)
```

Then confirm the cache is actually used: run a command that needs a passphrase
(`decrypt`, `sign`, `encrypt --sign`, `edit-key`) once — it prompts — and again
immediately afterwards. The second run must **not** prompt.

```bash
pqp sign -u alice -o doc.pqp.sig doc.txt   # prompts once, caches
pqp sign -u alice -o doc2.pqp.sig doc.txt  # no prompt (served from the agent)
```

## Manage

```bash
systemctl --user restart pqp-agent.service  # restart (wipes the cache)
systemctl --user stop pqp-agent.service     # stop and wipe the cache
systemctl --user disable pqp-agent.service  # don't start at login
journalctl --user -u pqp-agent.service -f   # follow logs
```

## Configuration

The service has no environment file and reads the normal pqp config
(`~/.config/pqp/pqp.toml`). To change the cache TTL or the socket path for the
service, either edit `--expire-time` in the unit or set them in the config:

```toml
[agent]
expire-time = "8h"
# unix-socket-path = "/run/user/1000/pqp-agent.sock"
```

## Troubleshooting

- **`Failed to start ... status=2` / "unrecognized subcommand 'agent'"** —
  the `pqp` at the unit's `ExecStart` path predates the `agent` command.
  Reinstall/rebuild and point `ExecStart` at the new binary.
- **`another pqp agent is already listening`** — a manually started agent is
  already running; stop it (`pqp agent --stop`) or the service.
- **The CLI still prompts** — the client and the agent resolved different
  socket paths. Check `systemctl --user show pqp-agent.service -p MainPID` and
  the socket printed in the journal, then compare with what `pqp` resolves.
- **Permission errors under a hardened sandbox** — the unit mounts `$HOME`
  read-only (`ProtectHome=read-only`). If you point `PQP_HOME` at a writable
  directory inside `$HOME`, add it to `ReadWritePaths=` in a drop-in
  (`systemctl --user edit pqp-agent.service`).
