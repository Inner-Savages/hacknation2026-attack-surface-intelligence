# Lab

Podsieć `172.28.0.0/24`, most `br-asilab`.

| Host | IP | Rola |
|---|---|---|
| web-plain | .10 | zwykły nginx |
| web-cms | .11 | imitacja WordPressa (meta generator, ciasteczko, `/wp-login.php`) |
| web-staging | .12 | staging (`X-Env`, tytuł STAGING, `/admin/`) |
| flapper | .20 | host niestabilny: 300 s up / 300 s down (`FLAP_UP`, `FLAP_DOWN`) |
| client | .100 | generator ruchu |

```
docker compose -f lab/docker-compose.yml up -d
sudo tcpdump -ni br-asilab tcp port 80     # ruch widoczny na hoście
nmap -sn 172.28.0.0/24                      # skan z hosta
docker compose -f lab/docker-compose.yml down
```
