.PHONY: build test sensor-caps lab-up lab-down sensor images

IMAGE_PREFIX ?= ghcr.io/inner-savages/silence-on-the-wire

# Obrazy sensora i generatora ruchu, otagowane tak jak w rejestrze, więc
# nakładki compose używają ich lokalnie bez pobierania.
images:
	docker build --target sensor  -t $(IMAGE_PREFIX)/sensor:latest .
	docker build --target traffic -t $(IMAGE_PREFIX)/traffic:latest .

build:
	go build -o bin/sensor ./cmd/sensor

test:
	go vet ./...
	go test ./...

# Nadaje binarce tylko CAP_NET_RAW, żeby nie uruchamiać sensora jako root.
sensor-caps: build
	sudo setcap cap_net_raw+ep bin/sensor

sensor: sensor-caps
	./bin/sensor -i br-asilab -net 172.28.0.0/24 -learn 30s

lab-up:
	docker compose -f lab/docker-compose.yml up -d

lab-down:
	docker compose -f lab/docker-compose.yml down
