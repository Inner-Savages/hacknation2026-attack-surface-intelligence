# CBI AGH lab templates + Silence on the Wire overlay

`upstream/` is the set of example environments the challenge organizers (Information
Security Center of AGH University of Krakow, CBI AGH) shared with HackNation 2026
participants. The files are unchanged from the original archive (the only difference:
`quickstart.sh` is marked executable, as its README expects). 

See `upstream/README.md` (Polish) for the stacks and their quickstart.

Our additions live next to it and never modify the upstream files:

| File | Purpose |
|---|---|
| `traffic-custom-network.yml` | compose overlay for `upstream/docker-compose-custom-network.yml`: background traffic, a flapping host and the passive sensor (on every Docker bridge, `-i 'br-*'`); it adds services only and never redefines the organizers' services or networks, so their `quickstart.sh` keeps working |
| `scenario.sh` | scripted scenario on that stack (banner change, service stop/start, new host, flapper) that prints the expected sensor events |

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml up -d
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml logs -f sensor

lab/agh/scenario.sh          # optional argument: path to another copy of the template
```

Without the overlay (`-f lab/agh/traffic-custom-network.yml`) the stack behaves exactly as
the organizers ship it. The overlay uses only published images
(`ghcr.io/inner-savages/silence-on-the-wire/{sensor,traffic}`), no local paths, so it also
works with a copy of the templates kept elsewhere.
