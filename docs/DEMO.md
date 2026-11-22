# Scenariusz demo

Czas: ok. 8–10 min. Wszystkie polecenia uruchamiamy z katalogu głównego repozytorium. Wymagania: Go 1.26+, `nmap`,
Docker z Compose; obrazy `ghcr.io/inner-savages/silence-on-the-wire/{sensor,trigger,traffic}` pobierane z rejestru
albo zbudowane lokalnie (`make images`).

## Co sprawdzono na żywo (2026-11-22, ta maszyna)

| Krok | Status |
|---|---|
| `make build`, `make console` | sprawdzone, buduje się |
| `docker compose … config -q` dla szablonu AGH z nakładką | sprawdzone, poprawny |
| Stack AGH z nakładką działający od godzin (sensor, trigger, traffic, flapper) | sprawdzone: zdarzenia sensora, `GET /healthz` triggera i znaleziska w logach poniżej pochodzą z tego stacku |
| Skan, `scanner diff`, `scanner export` (CSV, JSON, nmap XML, DefectDojo `-dry-run`) | sprawdzone, wyniki poniżej |
| Konsola `-demo`: rejestracja, logowanie, `GET /api/summary` | sprawdzone (dane syntetyczne) |
| `lab/agh/scenario.sh` w całości | **nie uruchomiono ponownie**: zatrzymuje `flask-app` na działającym, współdzielonym stacku. Skrypt przeczytano; jego efekty (np. `service_changed` na `flask-app`) widać w logach sensora z wcześniejszego uruchomienia. Przed pokazem odpal go sam |
| Wejście do konsoli w przeglądarce (UI) | **nie sprawdzono wzrokowo**, tylko API (`/` zwraca 200) |

Poniższe wyniki to rzeczywiste wyjścia; adresy IP kontenerów, czasy i daty będą inne przy Twoim uruchomieniu.

## Krok 0. Budowa

```bash
make build console
```

Oczekiwane: powstają `bin/sensor`, `bin/scanner`, `bin/trigger`, `bin/traffic`, `bin/edgegate`, `bin/console`.

## Krok 1. Laboratorium AGH (custom-network) z nakładką

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml up -d
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml ps
```

Oczekiwane: usługi `custom-api`, `postgres`, `rabbitmq`, `gitea`, `flask-app` (szablon AGH) oraz `traffic`, `flapper`,
`sensor`, `trigger` (nakładka) w stanie `Up`. Sensor przez pierwsze 30 s (`-learn 30s`) uczy się po cichu, więc
nie ma zdarzeń: to baseline.

## Krok 2. Skan odniesienia (scanner)

Porty opublikowane przez szablon AGH: 2223 (ssh gitei), 3001 (gitea), 5673 (amqp), 8787 (nginx),
8888 (httpbin), 15432 (postgres), 15673 (panel RabbitMQ).

```bash
P=2223,3001,5673,8787,8888,15432,15673
./bin/scanner -t 127.0.0.1 -p $P -Pn -o scan1.json
```

Oczekiwane (zmierzone): w logu linia `nmap -sT -sV … --max-rate 300 --host-timeout 300s`
(bez NSE, bez OS-detection), potem `chunk 1/1: 1 targets, 1 up, 48.03s, ok`,
`probed 4 web services`, `fingerprinted`, `done in 48.03s: 1 hosts up, 7 open ports`. Skan trwa ok. 48 s, bo `-sV`
na usługach AMQP i PostgreSQL jest wolny.

## Krok 3. Co rozpoznano (fingerprinting)

```bash
./bin/scanner export -o scan1.csv scan1.json && column -s, -t scan1.csv | cut -c1-200
```

Zmierzone wartości kolumn `technologies` i `confidence` (skrót):

| Port | Technologie (confidence) |
|---|---|
| 3001 | Gitea 0,99; Setup / installation page 0,80 (tag `setup-page`); Go net/http 0,80; Login page 0,60 |
| 8787 | nginx 0,98; Default web server page 0,90 (tag `default-page`) |
| 8888 | httpbin 0,90; gunicorn 19.9.0 0,90 |
| 15673 | Cowboy 0,98; RabbitMQ Management 0,95; Admin panel 0,60 (tag `admin-panel`) |
| 2223 / 5673 / 15432 | OpenSSH 10.3 0,95 / AMQP broker 0,85 / PostgreSQL 0,95 |

Pewność to noisy-OR wag dowodów (`1 − Π(1 − w)`); patrz `ARCHITECTURE.md`, sekcja 6.2.

## Krok 4. Zmiana między przebiegami (diff)

Własna, jednorazowa usługa, żeby nie ruszać stacku AGH:

```bash
docker run -d --rm --name asi-docs-tmp -p 127.0.0.1:18787:80 nginx:alpine
./bin/scanner -t 127.0.0.1 -p $P,18787 -Pn -o scan2.json
docker stop asi-docs-tmp
./bin/scanner -t 127.0.0.1 -p $P,18787 -Pn -o scan3.json
./bin/scanner diff scan1.json scan2.json
./bin/scanner diff scan2.json scan3.json
```

Oczekiwane (zmierzone):

```
scan 2026-11-22 06:39:17 (1 hosts, 7 services) -> scan 2026-11-22 06:40:07 (1 hosts, 8 services)
warning: scans used different nmap settings; some differences may come from that, not from the network

~ 127.0.0.1
  + 18787/tcp http nginx 1.31.9 "Welcome to nginx!"

0 new hosts, 0 gone hosts, 1 new services, 0 gone services, 0 changed services
```

i po zatrzymaniu usługi `- 18787/tcp http nginx 1.31.9 "Welcome to nginx!"`, `1 gone services`. Ostrzeżenie
w pierwszym diffie wynika z innej listy portów (`-p`) między skanami: to zamierzona cecha, nie błąd.
Własny skrypt AGH (`lab/agh/upstream/quickstart.sh change`) zatrzymuje usługę na 8787 i też da się pokazać diffem.

## Krok 5. Sensor i trigger w akcji

Sensor i trigger już działają w stacku z kroku 1. Podgląd zdarzeń pasywnych i skanów wzbudzonych przez nie:

```bash
C="docker compose -f lab/agh/upstream/docker-compose-custom-network.yml -f lab/agh/traffic-custom-network.yml"
$C logs --no-log-prefix sensor  | grep '"type"'
$C logs --no-log-prefix trigger | grep -E 'trigger: .* (scan|finding) '
curl -s 127.0.0.1:8099/healthz
```

Oczekiwane (przykłady z żywego stacku):

```
{"type":"service_changed","ip":"172.20.0.4","port":80,"proto":"tcp","old":"http; server=nginx/1.31.9","new":"http; server=nginx", ... "source":"passive","sensor":"agh-lab"}
{"type":"service_closed","ip":"172.20.0.5","port":80,"proto":"tcp","old":"active", ...}
trigger: 05:42:58 scan 172.20.0.5:80 (scan-service, 2 events)
trigger: 05:43:04 finding 172.20.0.5:80 scan-service: scanned 80/http [nginx 1.31.9, Default web server page]
```

`172.20.0.5` to `flapper` (host niestabilny: usługa działa 60 s i milczy 60 s). Sensor zgłasza na przemian `service_closed`
(RST: kontener żyje, port zamknięty) i `service_back`, a trigger przy każdej zmianie skanuje ten port. Healthz
pokazuje liczniki triggera, np. w zmierzonym momencie `"accepted":390`, `"scans":228` oraz powody odrzuceń
(`dropped: scanner's own address`, `quiet: address just scanned`, `verified alive recently`): to dowód, że polityka
ogranicza ruch aktywny.

## Krok 6. Scenariusz skryptowany AGH

```bash
lab/agh/scenario.sh
```

Skrypt (ok. 4–5 min) przed każdym krokiem wypisuje, czego się spodziewać:

1. start stacku, sensor uczy się ok. 45 s (brak zdarzeń),
2. zmiana bannera na `flask-app` → `service_changed`, skan `scan-service`, w znalezisku zmiana wersji,
3. `docker compose stop flask-app` → po ok. 80 s `host_silent` i `service_silent`, werdykty `gone-confirmed` / `down-confirmed`,
4. `docker compose start flask-app` → `host_back`, `service_back`, skan hosta,
5. nowy kontener `asi-intruder` → `host_new`, `service_new`, skan z rozpoznanym nginx,
6. flapper przez cały czas → na zmianę `service_closed` i `service_back`.

Na koniec drukuje zdarzenia sensora i znaleziska triggera. Zatrzymanie stacku:

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml down
```

## Krok 7. Eksport i DefectDojo

```bash
./bin/scanner export -format json -o scan.json.out scan2.json
./bin/scanner export -format nmap -o scan.xml scan2.json
./bin/scanner export -format defectdojo -dry-run scan2.json | head -40
```

Oczekiwane (zmierzone): `dry run: 5 finding(s) would be sent to "Silence on the Wire" / "Continuous discovery" /
"Silence on the Wire observations"`, potem lista findingów z `severity: Info`, tagami (`silence-on-the-wire`,
`setup-page`, `default-page`, `admin-panel`), `endpoints` i stabilnym `unique_id_from_tool`
(np. `sotw:setup-page:127.0.0.1:tcp:3001`), dzięki któremu ponowny eksport nie tworzy duplikatów.
Prawdziwy wysyłany eksport: `export DEFECTDOJO_TOKEN=… && ./bin/scanner export -format defectdojo -url <adres> scan2.json`
(lokalną instancję daje `lab/defectdojo/`); w tym dokumencie wysyłki do DefectDojo **nie** wykonano.

## Krok 8. Konsola operatora

```bash
ASI_CENTRAL_TOKEN=demo-token ./bin/console -demo -listen 127.0.0.1:18081 -data-dir var/console
```

Otwórz `http://127.0.0.1:18081/`, zarejestruj pierwsze konto (zostaje administratorem), zaloguj się. Oczekiwane
w trybie demo (dane syntetyczne, nie z laboratorium AGH): 137 sensorów i 217 przypadków; `GET /api/summary` po zalogowaniu
zwraca liczniki kart (`nowe`, `do_weryfikacji`, `potwierdzony`, `falszywy_alarm`, `zamkniety`) i stan floty
(`online`/`offline`/`total`). Bez logowania endpointy zwracają 401. Konsola na `main` pokazuje eskalacje i flotę
sensorów; dashboard wyników skanów z diffem, formularz importu, pełne role i szyfrowanie są w pracach (patrz
`ARCHITECTURE.md`, sekcja 9, statusy **PR w toku**).

## Krok 9. Bramka AI (opcjonalnie)

```bash
make cascade50-demo     # modele + bramka + konsola; modele ~2,5 GB pobierane i weryfikowane SHA256
```

**Nie uruchomiono** podczas przygotowania tej dokumentacji (duże pobranie). Szczegóły: `deploy/cascade50/README.md`.
Bez bramki sensor łączy się z triggerem bezpośrednio (tak jak w kroku 5).

## Sprzątanie

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml down
rm -f scan1.json scan2.json scan3.json scan1.csv scan.xml scan.json.out
```
