.PHONY: build test sensor-caps lab-up lab-down sensor

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
