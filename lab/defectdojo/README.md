# Local DefectDojo

A throwaway [DefectDojo](https://defectdojo.com) for trying `scanner export -format
defectdojo`. It is the official Docker Compose stack; `local.yml` only binds it to
127.0.0.1 and lowers the number of worker processes (about 800 MB of RAM when idle). Do not send lab results to
public demo instances.

```bash
git clone --depth 1 -b 3.5.202 https://github.com/DefectDojo/django-DefectDojo.git /tmp/defectdojo
export DD_IMAGE_REGISTRY=docker.io DJANGO_VERSION=3.5.202 NGINX_VERSION=3.5.202
DD="docker compose -p dojo -f /tmp/defectdojo/docker-compose.yml -f $PWD/lab/defectdojo/local.yml"
eval "$DD up -d --no-build"                 # about a minute the first time
(umask 077; eval "$DD exec -T uwsgi python3 manage.py drf_create_token admin" \
  | grep -oE '[0-9a-f]{40}' > dojo.token)
./bin/scanner export -format defectdojo -url http://127.0.0.1:18080 -token-file dojo.token scan.json
eval "$DD down -v"                          # removes the data too
```

The web UI is at <http://127.0.0.1:18080>; the generated admin password is in the
initializer's log (`docker logs dojo-initializer-1`).
