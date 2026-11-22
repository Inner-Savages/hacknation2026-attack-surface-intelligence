# Public demo: https://silent.zjadlabymciastko.net

One VM, one compose project. The operator console runs in demo+live mode
(synthetic fleet plus real events) and is reachable **only** through a Cloudflare
Tunnel gated by Cloudflare Access (one-time PIN). No port is published on the
host. Console accounts are created by the operator; self-registration is off.

```
browser -> Cloudflare Access (OTP) -> Tunnel -> cloudflared --(compose net "demo")--> console:18081
```

Files: `compose.yaml`, `.env.example`, `setup.sh` (secrets), `lab.override.yml`
(optional lab), `systemd/` (auto-update and start-on-boot units).

## 1. Prepare a clean Debian/Ubuntu VM

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh        # Docker Engine + compose plugin
sudo usermod -aG docker "$USER" && newgrp docker
```

Log in to ghcr.io (the repo is private) with a classic PAT that has only
`read:packages`:

```bash
echo "$GHCR_PAT" | docker login ghcr.io -u <github-user> --password-stdin
```

## 2. Cloudflare (dashboard, once)

1. Zero Trust > Networks > Tunnels > create a tunnel (cloudflared), copy the **token**.
2. Public hostname `silent.zjadlabymciastko.net` -> service `http://console:18081`
   (ingress is managed remotely, nothing to configure in this repo).
3. Zero Trust > Access > Applications: self-hosted app for that hostname, policy
   "Allow" with the jury/team e-mails, login method One-time PIN.

## 3. Install and start

```bash
sudo git clone https://github.com/Inner-Savages/silence-on-the-wire /opt/silent-demo-src
sudo ln -sfn /opt/silent-demo-src/deploy/demo /opt/silent-demo   # units expect /opt/silent-demo
cd /opt/silent-demo && sudo chown -R "$USER" /opt/silent-demo-src
./setup.sh            # creates secrets/ and .env, prints the admin and viewer passwords once
$EDITOR .env          # set TUNNEL_TOKEN; optionally SHODAN_API_KEY, CENSYS_*, NVD_API_KEY
docker compose pull && docker compose up -d
docker compose ps     # console should become "healthy"
```

Sign in at the public URL (after the Access PIN) as `admin` with
`secrets/admin_password`. The first account is the admin created from that file;
there is no setup screen to race for, because the admin exists before the first request.

Third-party keys (Shodan, Censys, NVD, LLM) are read **only** from environment
variables (`.env`, mode 0600, git-ignored). They are never baked into the image
or stored in the repo. The data key (`secrets/data_key`) encrypts the console's
state at rest (AES-256-GCM); **back it up** — without it the volume is unreadable.

### Read-only access for the jury

Set `ASI_VIEWER_LOGIN=jury` in `.env` (default in `.env.example`); the account is
created with the built-in `viewer` role and the password from
`secrets/viewer_password`. `viewer` can read cases, sensors, logs and rules and
nothing else (verified: `POST /api/exposure/run` and `GET /api/config` give 403).
Seeding is idempotent: existing accounts are never overwritten, so to rotate a
password change it in the UI (or delete the user and restart).

### Self-registration

`ASI_ALLOW_REGISTRATION=false` (default in this deployment) makes
`POST /api/register` return 403 once any account exists. It is still possible to
create the very first account while the user list is empty (a safety net for a
console started without `ASI_ADMIN_LOGIN`). Without the variable the console
behaves as before (registration open) — this only changes the deployment.

## 4. Updates

Pull-based, no inbound access needed. Images come from CI on every merge to
`main` (`:latest`) and on tags. Install the timer:

```bash
sudo cp systemd/silent-demo*.service systemd/silent-demo-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now silent-demo.service silent-demo-update.timer
systemctl list-timers silent-demo-update.timer
journalctl -u silent-demo-update.service -n 20
```

Every 5 minutes it runs `docker compose pull && docker compose up -d`; only
services whose image changed are recreated (the data volume survives). Pin a
release with `SOTW_TAG=0.5` in `.env` instead of `latest` if you want stability
during judging. (Alternative: run Watchtower; the timer is preferred here because
it is auditable and does not need the Docker socket in a container.)

## 5. Optional: live lab (AGH custom-network) feeding the console

The sensor needs `network_mode: host` and `CAP_NET_RAW` to see the Docker bridges
of the lab, so it cannot sit on the isolated compose network. Honest consequences:

- The sensor/trigger containers share the VM's network namespace. The sensor is
  passive and has `cap_drop: ALL` + `NET_RAW` only, the trigger has no caps, but
  they are not isolated from the host network like the console is.
- Host networking cannot resolve `console`, so the `lab` profile starts
  `lab-relay`, which exposes the console on **127.0.0.1:18081 only** (not on the
  LAN). This is the single published port, and only with `--profile lab`.
- The trigger actively scans. Its allowlist is the two fixed lab subnets
  (`172.29.10.0/24`, `172.29.11.0/24`); it refuses anything outside, and the
  sensor ignores the `br-demo` bridge (console + tunnel).
- The organizers' lab file publishes its own ports on the host (8888, 15432,
  5673, 15673, ...). Firewall them or keep the VM off untrusted networks.
- `POST /logs` (sensor feed) is what the console ingests from the sensor.
  `POST /events` expects cascade edge-gate escalation envelopes (see
  `deploy/cascade50`), not raw sensor events. Both need the bearer token
  (`ASI_CENTRAL_TOKEN`, 401 without it).
- `POST /findings` is where the trigger ships every targeted-scan result
  (`-findings-url http://127.0.0.1:18081/findings`, same token, 401 without
  it). The console correlates a finding with the open case for that host
  (verdict + services + diff as an audited note) or opens a new case, so the
  demo shows scan results instead of staying empty; the live feed labels them
  `WERYFIKACJA`. The "scan" action on a case can ask the trigger for a
  targeted scan when the console has `ASI_TRIGGER_URL`/`ASI_TRIGGER_TOKEN`
  set (not wired in the demo compose: the console is on an isolated network
  and the trigger listens on the host's loopback).

```bash
cd /opt/silent-demo && docker compose --profile lab up -d lab-relay
cd /opt/silent-demo-src && set -a && . deploy/demo/.env && set +a
docker compose -p demo-lab \
  -f lab/agh/upstream/docker-compose-custom-network.yml \
  -f lab/agh/traffic-custom-network.yml \
  -f deploy/demo/lab.override.yml up -d
docker compose -p demo-lab -f ... logs -f sensor trigger
```

### TLS findings in the lab

`lab.override.yml` also starts four tiny TLS services (`alpine/openssl`,
`openssl s_server` on :443) on the frontend network, so the console's **TLS** tab
has real findings. Certificates and keys are generated in the container at start
(nothing in the repo):

| service | IP | certificate | finding |
|---|---|---|---|
| `tls-selfsigned` | 172.29.10.50 | self-signed, 365 days | `tls_self_signed` (warn) |
| `tls-expiring` | 172.29.10.51 | "Demo Internal CA", 10 days left | `tls_expiring` (high, 14-day threshold) |
| `tls-expired` | 172.29.10.52 | "Demo Internal CA", expired 3 days ago | `tls_expired` (crit) |
| `tls-rotate` | 172.29.10.53 | "Demo Internal CA", swapped for "Unknown Rogue CA" after `TLS_ROTATE_AFTER` s (default 900) | `tls_ca_change` (high) |

How they reach the TLS tab: the console only probes certificates during
**control scans of silent hosts** (ground truth), then the TLS monitor evaluates
those records. So `tls-poke` touches the four services a few times after the
sensor's learning window (the sensor reports them via `/logs`), then leaves them
alone and they go `host_silent`. Steady traffic would keep them out of the scan.
The default silence threshold is 60 min; for the demo lower it once and run the
scans (admin session cookie in `cj`):

```bash
C=https://silent.zjadlabymciastko.net
curl -s -b cj -XPOST -H 'Content-Type: application/json' -d '{"gt_silent_min":1}' $C/api/config
curl -s -b cj -XPOST $C/api/groundtruth/run; sleep 15
curl -s -b cj -XPOST $C/api/tls/run;         sleep 3
curl -s -b cj $C/api/tls
```

The CA change is raised on the first TLS run after the swap (run both scans once
before and once after `TLS_ROTATE_AFTER`). Re-poke after a restart with
`docker compose -p demo-lab -f ... up -d --force-recreate tls-poke`.

## Operations

| | |
|---|---|
| status / logs | `docker compose ps`, `docker compose logs -f console cloudflared` |
| stop everything | `docker compose --profile lab down` (keeps data); `down -v` wipes the volume |
| rotate the shared token | edit `ASI_CENTRAL_TOKEN` in `.env`, `docker compose up -d`, update sensors |
| tunnel down | check `TUNNEL_TOKEN` and `docker compose logs cloudflared` |

## Known limits

- Single VM, no HA; state is one Docker volume (back up `console-data` and `secrets/`).
- The console speaks plain HTTP on the private compose network; TLS is terminated by Cloudflare.
- `:latest` auto-update means a bad merge to `main` reaches the demo within 5 minutes; pin `SOTW_TAG` for the judging window.
