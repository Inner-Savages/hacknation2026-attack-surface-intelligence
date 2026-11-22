# Scenariusz demo

Czas: ok. 8–10 min. Dwa warianty: **[A. publiczne demo](#a-publiczne-demo-co-klika-jury)** (konsola w przeglądarce) i
**[B. lokalnie z terminala](#b-lokalnie-z-terminala)** (skaner, diff, eksport, laboratorium AGH). Polecenia z B uruchamiamy
z katalogu głównego repozytorium; wymagania: Go 1.26+, `nmap`, `libpcap-dev`, Docker z Compose.

Adresy IP kontenerów, czasy i daty będą inne przy Twoim uruchomieniu. Haseł i tokenów w tym pliku nie ma. Co i jak
sprawdzono: [na końcu](#co-sprawdzono).

---

## A. Publiczne demo: co klika jury

Adres: <https://silent.zjadlabymciastko.net>. Na czas oceny od razu pojawia się ekran logowania konsoli (poza nim najpierw
Cloudflare Access z PIN-em na e-mail). Zaloguj się kontem `jury` (rola `viewer`, tylko odczyt; hasło od zespołu).
Samorejestracja jest wyłączona. Zakładki wybiera się z menu obok nazwy projektu, na starcie „Alerty ▾”.

Konsola łączy **flotę syntetyczną** (137 sensorów, 217 spraw) z **prawdziwymi zdarzeniami** z laboratorium AGH
(sensor i trigger na tej samej VM). Nagłówek pokazuje „DANE DEMO” i „LIVE · tylko edge”.

| # | Zakładka | Co kliknąć | Czego się spodziewać |
|---|---|---|---|
| 1 | **Alerty** (start) | zobacz liczniki, otwórz kartę sprawy | pięć liczników: Nowe, Do weryfikacji, Potwierdzone, Fałszywe alarmy, Zamknięte (liczby zmieniają się na żywo). Sprawa ma historię i notatki. Wyniki skanów triggera (werdykty) pojawiają się jako notatki albo nowe sprawy |
| 2 | **Mapa** | przesuń suwak czasu, kliknij host | graf hostów i usług z pasywnego rejestru sensora oraz oś czasu. Na demo: hosty `172.29.10.x` i `172.29.11.x` z labu AGH; flapper pojawia się na przemian jako `service_closed` i `service_back` |
| 3 | **Ekspozycja** | otwórz | porównanie widoku od środka z widokiem z internetu (Shodan/Censys). Bez kluczy API komunikat „Korelacja z internetem nie jest skonfigurowana”: to oczekiwane, klucze ustawia administrator |
| 4 | **TLS** | otwórz | monitor certyfikatów (progi 30/14/7 dni, self-signed, zmiana CA, słabe szyfry). Na demo znaleziska z usług TLS w labie: certyfikat wygasły, bliski wygaśnięcia i self-signed (liczba zależy od momentu skanu kontrolnego) |
| 5 | **Zasoby** | otwórz | inwentarz z klasyfikacją urządzeń z ruchu (drukarka, kamera, IoT, serwer…). W labie Dockera adres MAC nic nie mówi (`02:42:…`), więc klasy (`baza`, `broker`, `git`, `web`…) wynikają z portów, produktów i tytułów HTTP. To heurystyka, pojedyncze hosty bywają sklasyfikowane błędnie |
| 6 | **Ryzyko** | kliknij Top 10 / Top 25 / Top 50 | liczniki Krytyczne / Wysokie / Średnie i tabela hostów z wynikiem 0–100 oraz „głównymi czynnikami” (np. „najwyższa ocena kaskady modeli 0.98”). Na szczycie hosty z labu ze znaleziskami TLS (`172.29.10.52`, `.51`) |
| 7 | **Logi live** | otwórz, „Wstrzymaj” | strumień zdarzeń `SENSOR` i `ALERT`; zdarzenia triggera z etykietą `WERYFIKACJA`. Pasek „AI: wyłączone”: bramka i analiza AI są na demo wyłączone |
| 8 | **Sensory** | otwórz | lista sensorów z oznaczeniem offline |
| 9 | **Cele i import** | zobacz „Dodaj cel ręcznie”, „Import pliku” | formularze są widoczne, ale jako `viewer` każdy zapis kończy się kodem 403: o uprawnieniach decyduje serwer. Dodawanie: `admin` albo `editor`; edycja wpisów także `analyst` |
| 10 | **Reguły** | otwórz | odczyt reguł triage; zmiana wymaga uprawnienia `rules:write` |
| – | **Ustawienia**, **Role** | – | dla `viewer` zakładki są ukryte (to jest rozgraniczenie ról); administrator zobaczy ustawienia i edytor ról |

Rozgraniczenie ról pokaż na żywo: zaloguj się jako `jury`, spróbuj dodać cel (403), potem jako `admin` dodaj cel, zaimportuj plik,
edytuj wpis i zobacz zakładkę „Role” (cztery wbudowane role plus własne).

### Scenariusz dla administratora (po stronie zespołu)

1. Zakładka **Cele i import** → „Dodaj cel ręcznie”: wpisz np. `10.0.0.9`; wpis pojawia się w tabeli.
2. „Import pliku” → „Lista celów (txt / CSV / JSON)”: wczytaj CSV; odpowiedź podaje, ile dodano, ile duplikatów i które pozycje odrzucono (np. `bad host!`).
3. „Wynik skanu (JSON / CSV)”: wczytaj `scan1.json` z wariantu B, potem `scan2.json`; kafelek **Ostatni diff** pokazuje zmiany (`+1 usług`).
4. **Edytuj** przy wpisie (np. Gitea): zmień tytuł, tagi, notatkę, status; wpis dostaje znacznik „edytowane”.
5. Wczytaj skan ponownie: edycja zostaje (nadpisania są trzymane osobno od danych skanu).
6. **Role** → utwórz własną rolę z wybranych uprawnień i przypisz ją użytkownikowi; zmiana trafia do audytu.

---

## B. Lokalnie z terminala

### Krok 0. Budowa

```bash
make build console
```

Oczekiwane: powstają `bin/sensor`, `bin/scanner`, `bin/trigger`, `bin/traffic`, `bin/edgegate`, `bin/console`.

### Krok 1. Laboratorium AGH (custom-network) z nakładką

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml up -d
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml ps
```

Oczekiwane: usługi `custom-api`, `postgres`, `rabbitmq`, `gitea`, `flask-app` (szablon AGH) oraz `traffic`, `flapper`,
`sensor`, `trigger` (nakładka) w stanie `Up`. Sensor przez pierwsze 30 s (`-learn 30s`) uczy się po cichu, więc
nie ma zdarzeń: to baseline.

### Krok 2. Skan odniesienia

Porty opublikowane przez szablon AGH: 2223 (ssh gitei), 3001 (gitea), 5673 (amqp), 8787 (nginx),
8888 (httpbin), 15432 (postgres), 15673 (panel RabbitMQ).

```bash
P=2223,3001,5673,8787,8888,15432,15673
./bin/scanner -t 127.0.0.1 -p $P -Pn -o scan1.json
```

Oczekiwane (zmierzone): `nmap -sT -sV … --max-rate 300 --host-timeout 300s` (bez NSE i OS-detection), potem

```
chunk 1: 1 targets (tail shared between workers), 1 up, 5.03s, ok; 1/1 targets
probed 4 web services in 27ms
fingerprinted in 19ms
done in 5.03s: 1 hosts up, 7 open ports
```

Wzbogacenie o CVE: dopisz `-cve` (potrzebuje sieci do NVD i EPSS).

### Krok 3. Co rozpoznano (fingerprinting)

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

### Krok 4. Zmiana między przebiegami (diff)

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
~ 127.0.0.1
  + 18787/tcp http nginx 1.31.9 "Welcome to nginx!"

0 new hosts, 0 gone hosts, 1 new services, 0 gone services, 0 changed services
```

i po zatrzymaniu usługi `- 18787/tcp http nginx 1.31.9 "Welcome to nginx!"`, `1 gone services`. Ostrzeżenie
„scans used different nmap settings” w pierwszym diffie wynika z innej listy portów (`-p`) między skanami: to zamierzona
cecha, nie błąd.

### Krok 5. Sensor i trigger w akcji

Sensor i trigger działają w stacku z kroku 1. Podgląd zdarzeń pasywnych i skanów wzbudzonych przez nie:

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

`172.20.0.5` to `flapper` (usługa działa 60 s i milczy 60 s), `172.20.0.4` to `flask-app`. Sensor zgłasza na przemian
`service_closed` (RST: kontener żyje, port zamknięty) i `service_back`, a trigger przy każdej zmianie skanuje ten port. Healthz
pokazuje liczniki triggera, np. w zmierzonym momencie `"accepted":390`, `"scans":228` oraz powody odrzuceń
(`dropped: scanner's own address`, `quiet: address just scanned`, `verified alive recently`): to dowód, że polityka
ogranicza ruch aktywny.

### Krok 6. Konsola lokalnie, z prawdziwymi zdarzeniami sensora

```bash
ASI_CENTRAL_TOKEN=<token> ASI_ADMIN_LOGIN=admin ASI_ADMIN_PASSWORD=<hasło> \
ASI_VIEWER_LOGIN=jury ASI_VIEWER_PASSWORD=<hasło> ASI_ALLOW_REGISTRATION=false \
./bin/console -demo -listen 127.0.0.1:18081 -data-dir var/console
```

Oczekiwane w logu: `data at rest: AES-256-GCM enabled (key: …/data.key (generated))`, `demo fleet seeded: 137 sensors, 217 cases`,
`self-registration disabled`, `operator console listening on 127.0.0.1:18081 (demo=true, …)`. Otwórz
`http://127.0.0.1:18081/`, zaloguj się i przejdź zakładki jak w wariancie A.

Żeby Mapa i Zasoby nie były puste, wyślij do konsoli zdarzenia z sensora z laboratorium (tak robi sensor na demo):

```bash
docker logs hacknation-custom-network-sensor-1 2>&1 | grep '"type"' | tail -300 > ev.jsonl
curl -s -X POST 127.0.0.1:18081/logs -H "Authorization: Bearer <token>" -H 'X-Sensor-Id: agh-lab' --data-binary @ev.jsonl -w ' %{http_code}\n'
```

Oczekiwane: `202`; `GET /api/map` (po zalogowaniu) zwraca hosty z lab AGH, a w zakładce Mapa pojawia się graf. Zmierzone: z 300 zdarzeń
4 hosty i 165 zdarzeń na osi czasu. Zasoby z takiej sieci mostowej bez zaimportowanego skanu są klasy „nieznane” albo `kontener`/`brama`.

### Krok 7. Import i edycja przez API (to samo, co robi formularz)

```bash
printf 'address,tags,note\n10.0.0.9,test,\n10.0.1.0/24,,\nbad host!,,\nexample.org,,\n' > t.csv
curl -s -c jar -X POST 127.0.0.1:18081/api/login -d '{"login":"admin","password":"<hasło>"}'
curl -s -b jar -X POST '127.0.0.1:18081/api/import?kind=targets' --data-binary @t.csv -H 'Content-Type: text/csv'
curl -s -b jar -X POST '127.0.0.1:18081/api/import?kind=scan' --data-binary @scan1.json
curl -s -b jar -X POST '127.0.0.1:18081/api/import?kind=scan' --data-binary @scan2.json
curl -s -b jar -X PUT '127.0.0.1:18081/api/overrides/svc:127.0.0.1:tcp:3001' \
     -d '{"title":"Gitea (zatwierdzone przez zespół)","tags":["krytyczne"],"note":"instalator otwarty","status":"potwierdzony"}'
curl -s -b jar -X POST '127.0.0.1:18081/api/import?kind=scan' --data-binary @scan3.json
curl -s -b jar 127.0.0.1:18081/api/inventory
```

Oczekiwane (zmierzone): import CSV z czterema pozycjami zwraca `"added":3`, `"rejected":1` i opis błędu dla `bad host!`;
drugi import skanu zwraca diff z `"new_services":1`; po trzecim wpis Gitea ma w odpowiedzi `override` (tytuł, tagi, notatka, status)
i `effective` z tymi wartościami; diff pokazuje `"gone_services":1`. Jako `viewer` te zapisy zwracają 403.

### Krok 8. Scenariusz skryptowany AGH

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

### Krok 9. Eksport i DefectDojo

```bash
./bin/scanner export -format json -o scan.json.out scan2.json
./bin/scanner export -format nmap -o scan.xml scan2.json
./bin/scanner export -format defectdojo -dry-run scan2.json | head -40
```

Oczekiwane (zmierzone): `dry run: 5 finding(s) would be sent to "Silence on the Wire" / "Continuous discovery" /
"Silence on the Wire observations"`, potem lista findingów z `severity: Info`, tagami (`silence-on-the-wire`,
`setup-page`, `default-page`, `admin-panel`), `endpoints` i stabilnym `unique_id_from_tool`
(np. `sotw:setup-page:127.0.0.1:tcp:3001`), dzięki któremu ponowny eksport nie tworzy duplikatów.
Prawdziwa wysyłka: `export DEFECTDOJO_TOKEN=… && ./bin/scanner export -format defectdojo -url <adres> scan2.json`
(lokalną instancję daje [`lab/defectdojo/`](../lab/defectdojo/README.md)). Na DefectDojo 3.5.202 pierwszy
eksport utworzył 8 findingów, powtórzony: 0 nowych, 8 bez zmian ([#12](https://github.com/Inner-Savages/silence-on-the-wire/pull/12)).

### Krok 10. Harmonogram (CLI)

```bash
mkdir -p results
./bin/scanner schedule -window 22:00-05:00 -tz Europe/Warsaw -every daily@22:00 \
  -checkpoint state.jsonl -out results -f targets.txt -allow 10.0.0.0/16
```

Do pokazu od ręki: okno obejmujące bieżącą chwilę i jeden przebieg.

```bash
./bin/scanner schedule -window $(date +%H:%M)-$(date -d '+5 min' +%H:%M) -tz Europe/Warsaw -every once \
  -checkpoint demo.jsonl -out results -t 127.0.0.1 -allow 127.0.0.0/8 -p $P -Pn
```

Oczekiwane (zmierzone): `session 1: 1 targets, window closes at 10:59:00 CET` … `run 20261122T095421Z done: scanned for 5.027s
in 1 session(s), 1 chunks, 1 hosts up, 7 open ports -> results/scan-20261122T095421Z.json`. Gdy okno zamknie się w trakcie,
nmap jest zatrzymywany, a następne okno kontynuuje z punktu kontrolnego (przebieg 256 adresów w dwóch oknach:
[#14](https://github.com/Inner-Savages/silence-on-the-wire/pull/14)). Harmonogram działa z CLI, nie z UI konsoli.

### Krok 11. Bramka AI (opcjonalnie)

```bash
make cascade50-demo     # modele + bramka + konsola; modele ~2,5 GB pobierane i weryfikowane SHA256
```

Szczegóły: [`deploy/cascade50/README.md`](../deploy/cascade50/README.md). Na demo online bramka jest wyłączona;
sensor łączy się z triggerem bezpośrednio (krok 5).

### Sprzątanie

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml down
rm -f scan1.json scan2.json scan3.json scan1.csv scan.xml scan.json.out ev.jsonl jar t.csv demo.jsonl state.jsonl
rm -f results/scan-*.json && rmdir results
```

---

## Co sprawdzono

Stan z 2026-11-22.

| Krok | Jak sprawdzono |
|---|---|
| Budowa, `go vet`, `go test ./...` | uruchomione, wszystkie pakiety przechodzą |
| Skan labu AGH, fingerprinting, `scanner diff`, eksport (CSV, JSON, nmap XML, DefectDojo `-dry-run`) | uruchomione |
| Harmonogram | uruchomiony w otwartym oknie; przerwanie i wznowienie w oknach: przebieg w [#14](https://github.com/Inner-Savages/silence-on-the-wire/pull/14) |
| DefectDojo na żywo (3.5.202) | przebieg w [#12](https://github.com/Inner-Savages/silence-on-the-wire/pull/12) |
| Konsola `-demo` lokalnie: logowanie, zakładki, role (403 dla `viewer`), import CSV i skanu, diff, nadpisania, pliki `ASIE` | przeglądarka i API |
| Zasilenie Mapy zdarzeniami z labu (`POST /logs`) | API |
| Publiczny adres | ekran logowania dostępny; zakładki Mapa, TLS i Ryzyko na zrzutach w prezentacji |
| Bramka AI z modelami, Shodan/Censys z kluczami, `lab/agh/scenario.sh` w całości po ostatnich zmianach | nie uruchomiono ponownie |
