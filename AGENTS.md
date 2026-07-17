# AGENTS.md

## Cursor Cloud specific instructions

GOLDENROUTE is a Docker Compose stack (three cooperating containers) that turns a
Linux host into a transparent Tor gateway. There is no application runtime
(Node/Python/etc.) — everything runs in Alpine containers. See `README.md` and
`PROMT.md` for the full architecture.

### Services (all defined in `docker-compose.yml`)

| Service   | Networking          | Role |
|-----------|---------------------|------|
| `unbound` | bridge, publishes `:53` | DNS-over-TLS forwarder (Cloudflare/Google, `.ru` → Yandex). |
| `tor`     | bridge, publishes `:9050` SOCKS / `:9051` control | Sole outbound backend; obfs4 bridges via lyrebird. |
| `fw`      | `network_mode: host`, `NET_ADMIN`+`NET_RAW` | iptables NAT + redsocks; routes all foreign TCP through Tor. |

### Startup

The Docker daemon and Docker are provisioned into the VM snapshot, not the update
script. If `docker info` fails, start the daemon first: `sudo dockerd` (run it in a
background/tmux session; it does not persist across VM restarts).

Then, from the repo root:

- Build: `sudo docker compose build`
- Run the safe services: `sudo docker compose up -d unbound tor`

Docker commands need `sudo` here (the `ubuntu` user is not in the `docker` group).

### IMPORTANT caveats for this cloud VM

- **Do NOT run the `fw` service (`docker compose up fw`) on this VM.** `fw` uses
  `network_mode: host`, so its iptables rules apply to the VM's own network
  namespace. Its entrypoint REDIRECTs all foreign TCP (and QUIC/UDP 443 → DROP)
  from the host's OUTPUT chain into redsocks→Tor, which hijacks the agent VM's own
  outbound traffic. Its stop-time `cleanup` does **not** remove the NAT rules, so
  stopping the container leaves the VM pointing at a dead redsocks and can
  permanently break connectivity. To validate `fw` logic, run its image in an
  isolated (default bridge) network namespace with `--cap-add NET_ADMIN --cap-add
  NET_RAW --entrypoint sh` and exercise the `iptables` commands manually.
- **`ipset` does not work on this Firecracker kernel.** The VM kernel
  (`6.12.94+`) is monolithic with no `/lib/modules` and no `ip_set` /
  `hash:net` support, so `ipset create ... hash:net` fails with
  `Kernel error received: Invalid argument`. This makes `fw` unable to fully start
  here even in isolation (it loads ipsets first under `set -e`). The rest of `fw`'s
  logic — iptables NAT REDIRECT/RETURN and the QUIC DROP rules — works fine. This
  is an environment/kernel limitation, not a repo bug; full `fw` end-to-end
  requires a host whose kernel provides the `ip_set` modules.
- Full transparent-proxy end-to-end (LAN client → gateway) is not reproducible on
  a single cloud VM. Validate the components individually instead:
  - `unbound`: `nslookup example.com 127.0.0.1` (host port 53).
  - `tor`: `docker compose logs tor | grep "Bootstrapped 100%"`, then
    `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`
    (should return `"IsTor":true`).
- `tor` bootstrap depends on the obfs4 bridges in `tor/bridges.txt` being alive and
  on outbound network egress. Some bridges log `general SOCKS server failure`
  warnings; that is normal as long as one reaches `Bootstrapped 100%`. If it never
  bootstraps, refresh bridges from https://bridges.torproject.org.
- `unbound` publishes host port 53. Ensure nothing else (e.g. `systemd-resolved`)
  is bound to 53 before `up`.

### Lint / test / build

There is no linter, test suite, or language toolchain in this repo. "Build" means
building the Docker images (`sudo docker compose build`); "run" means
`sudo docker compose up -d`.
