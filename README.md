# live-wrap: any self-hosted app behind a passkey, with its state sealed

`ce wrap gitea && ce up gitea`. One catalog entry per app is the whole contribution:

```toml
[app]
name = "grafana"
image = "docker.io/grafana/grafana-oss:11.3.0@sha256:a0f881232a6fb71a0554a47d0fe2203b6888fe77f4cefb7ea62bed7eb54e13c3"
http = { port = 3000, health = "/api/health" }
state = { dirs = ["."], mount = "/var/lib/grafana", snapshot = "nightly" }
auth = { passkey = true, header = "X-WEBAUTH-USER" }
limits = { cpu = "100%", mem = "512M" }
skill = "Grafana. HTTP API at /api. The signed-in user comes from the passkey session."
env = { GF_AUTH_PROXY_ENABLED = "true", ... }
```

The catalog has seven entries: gitea, grafana, code-server, nextcloud, immich, home-assistant and ollama
(`ollama` needs a GPU node and is lint-only). All seven lint and dry-run. Gitea and grafana have run live.

## What it is made of

| Piece | One function |
|---|---|
| the app | the upstream image, unmodified, with CPU and memory caps from `[limits]`, `--cap-drop=ALL`, its port on loopback only |
| `wrap.auth` | forward-auth in front of the app, default deny. A request gets through only with a session the issuer signed for this app (in ce, `account-passkey` signs it after a passkey login). The proxy removes any user header the client sent, sets the header the app trusts, and keeps the session away from the app |
| `wrap.snapshot` | the app's state dirs as one archive, sealed with the snapshot key. `restore` refuses an archive whose bytes or seal do not match, and never writes over a state dir that is not empty |
| keys | the session issuer's and snapshot key's seeds (`WRAP_ISSUER_SEED`, `WRAP_SNAPSHOT_SEED` under `keys run`); restore and the gate need only the public halves |

## Commands

```sh
ce-wrap list | lint | dry-run <app> | pin <app>     # pin writes the image's sha256 digest into the entry
ce-wrap up <app>                                    # container, capped, healthy
ce-wrap auth <app> --bind A --upstream U            # the gate
ce-wrap snapshot <app>                              # stops the app, archives and seals, starts it again
ce-wrap rm <app> && ce-wrap restore <app> --from <manifest> && ce-wrap up <app>
```

## The recorded run (2026-11-21)

[`docs/runs/2026-11-21-gitea-grafana.json`](docs/runs/2026-11-21-gitea-grafana.json), page: <https://ce-net.github.io/live-wrap/>.

| | |
|---|---|
| gitea up | healthy in 13.8 s (15.4 s in total), 159 MiB of its 1 GiB cap |
| default deny | no session: 401. A client-sent `X-WEBAUTH-USER: admin` with no session: 401 |
| login | the session made user `alice` through reverse-proxy auto-registration, with no second password |
| push | `git push` through the gate in 0.9 s, using the session as the Basic password. Commit `2bbce5f9` |
| snapshot | 138 ms, 54 306 bytes, sha256 `26cc55ed…` |
| remove, restore | container and state deleted. A tampered copy was refused (`2506df59…` does not match the sealed `26cc55ed…`). The restore took 98 ms and gitea was up again in 2.7 s. `git clone` returned commit `2bbce5f9` and its README |
| grafana | healthy in 7.7 s, 69 MiB of 512 MiB. No session, a spoofed header and a gitea session were all refused with 401. With a session, `/api/user` returned `alice` with `authLabels: ["Auth Proxy"]`, and grafana's own login form is disabled |

Both sessions in this run came from a demo issuer key made for the run, standing in for `account-passkey`, so no
passkey login happened. The live systems were stopped and removed after the run.

## Not done yet

- The passkey login itself: `wrap.auth` checks sessions signed by the issuer key, but `account-passkey` is not yet
  wired to issue them for wrapped apps.
- Isolation on a shared machine: the app's port is on loopback only, but a local process that calls it directly with
  a user header gets in (grafana answered 200 to that in the run). The app must sit on a network that only `wrap.auth`
  reaches; in ce that is the membrane route. Not built.
- Nightly snapshots and shipping them to the blob store on a second node: `snapshot` runs on demand and keeps the
  archive on the same machine.
- `SKILL.md` from `[skill]`, and the health row in the `ops` cell.
- Live runs of code-server, nextcloud, immich and home-assistant. Their entries lint and dry-run only, and their
  images are not pinned. The nextcloud and home-assistant entries need a bootstrap step (user_saml, trusted proxy)
  that is not built.
- Per-architecture digests: `pin` records the multi-arch index digest that `docker pull` resolved.

Licence: Apache-2.0.
