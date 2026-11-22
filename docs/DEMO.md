# Scenariusz demo

Czas: ok. 8–10 min. Dwa warianty: **A. publiczne demo** (konsola w przeglądarce, to klika jury) i **B. lokalnie z
terminala** (skaner, diff, eksport, laboratorium AGH). Wszystkie polecenia z B uruchamiamy z katalogu głównego
repozytorium; wymagania: Go 1.26+, `nmap`, Docker z Compose.

## Co sprawdzono (2026-11-22, ta maszyna)

| Krok | Status |
|---|---|
| `make build`, `make console` | sprawdzone |
| Konsola `-demo` lokalnie (z poprawką #24): ekran logowania, logowanie jako `viewer`, zakładki Alerty, Ekspozycja, TLS, Zasoby, Ryzyko, Logi live, Cele i import | sprawdzone w przeglądarce (pane) i przez API |
| Role: `viewer` czyta, nie zapisuje (403 na import, edycję nadpisań, `/api/exposure/run`, `/api/tls/run`, `/api/groundtruth/run`, `/api/targets`; 403 na `/api/config`, `/api/users`, `/api/roles`, `/api/audit`) | sprawdzone przez API |
| Import listy celów (CSV), import skanów, diff, nadpisanie i jego zachowanie po ponownym imporcie | sprawdzone przez API |
| Szyfrowanie: pliki `users.json` i `inventory/scan.json` zaczynają się od `ASIE` | sprawdzone |
| Zasilenie Mapy rzeczywistymi zdarzeniami sensora z laboratorium AGH (`POST /logs`) | sprawdzone przez API (4 hosty, 165 zdarzeń) |
| Skan, `scanner diff`, `scanner export` (CSV, JSON, nmap XML, DefectDojo `-dry-run`) | sprawdzone (przebiegi z sekcji B) |
| Stack AGH z nakładką działający od godzin; logi sensora i triggera, `GET /healthz` triggera | sprawdzone |
| **Publiczny adres** `https://silent.zjadlabymciastko.net` | **nie sprawdzono** (Cloudflare Access z jednorazowym PIN-em); opis wariantu A pochodzi z lokalnej konsoli w tym samym trybie i z `deploy/demo/README.md` |
| `lab/agh/scenario.sh` w całości | **nie uruchomiono ponownie** (zatrzymuje `flask-app` na działającym, współdzielonym stacku); jego skutki (np. `service_changed`) widać w logach sensora z wcześniejszego przebiegu |
| Bramka AI (`make cascade50-demo`), wysyłka do prawdziwego DefectDojo, Shodan/Censys z kluczami, `scanner schedule` na żywo | **nie uruchomiono** |

Adresy IP kontenerów, czasy i daty będą inne przy Twoim uruchomieniu. Haseł i tokenów w tym pliku nie ma, podstaw własne.

---

## A. Publiczne demo: co klika jury

Adres: <https://silent.zjadlabymciastko.net>. Konsola jest za Cloudflare Access: najpierw podaj e-mail z listy
dozwolonych, wpisz jednorazowy PIN z poczty, dopiero potem pojawia się ekran logowania konsoli. Zaloguj się kontem
`jury` (rola `viewer`, tylko odczyt; hasło dostajesz od zespołu). Konto `admin` ma pełny dostęp. Samorejestracja jest wyłączona.

Konsola działa w trybie demo+live: **flota syntetyczna** (137 sensorów, 217 spraw) plus **prawdziwe zdarzenia** z laboratorium AGH
(sensor i trigger na tej samej VM). Nagłówek pokazuje „DANE DEMO” i „LIVE · tylko edge”.

| # | Zakładka | Co kliknąć | Czego się spodziewać |
|---|---|---|---|
| 1 | **Alerty** (start) | zobacz liczniki, otwórz kartę sprawy | pięć liczników: Nowe, Do weryfikacji, Potwierdzone, Fałszywe alarmy, Zamknięte (lokalnie na starcie: 40 / 67 / 27 / 22 / 63, liczby zmieniają się na żywo). Sprawa ma historię i notatki. Wyniki skanów triggera (werdykty) pojawiają się jako notatki albo nowe sprawy |
| 2 | **Mapa** | przesuń suwak czasu, kliknij host | graf hostów i usług z pasywnego rejestru sensora oraz oś czasu. Bez żywego sensora zakładka mówi „Mapa jest jeszcze pusta”; na demo zasilają ją zdarzenia z lab AGH (flapper pojawia się na przemian jako `service_closed` i `service_back`) |
| 3 | **Ekspozycja** | otwórz | porównanie widoku od środka z widokiem z internetu (Shodan/Censys). **Bez kluczy API komunikat: „Korelacja z internetem nie jest skonfigurowana”**; klucze ustawia administrator (to jest oczekiwane, nie błąd) |
| 4 | **TLS** | otwórz | monitor certyfikatów (progi 30/14/7 dni, self-signed, zmiana CA, słabe szyfry). Bez znalezisk: „Brak otwartych znalezień TLS”, pasek „Włączone · co 1h0m0s” |
| 5 | **Zasoby** | otwórz | inwentarz z klasyfikacją urządzeń z ruchu (drukarka, kamera, IoT, serwer…). Bez zdarzeń: „Inwentarz jest jeszcze pusty”. W labie Dockera sam adres MAC nic nie mówi (`02:42:…` = kontener), więc konkretne klasy (`baza`, `broker`, `git`, `web`…) pojawiają się po zaimportowaniu skanu tych hostów (od #28 klasyfikator używa portów, produktów i tytułów HTTP z importu; wg kodu, na żywo nie sprawdzano) |
| 6 | **Ryzyko** | kliknij Top 10 / Top 25 / Top 50 | liczniki Krytyczne / Wysokie / Średnie i tabela hostów z wynikiem 0–100 oraz „głównymi czynnikami” (np. „najwyższa ocena kaskady modeli 0.98”). Lokalnie na start: 219 hostów w scoringu, najwyższy wynik 24,5 (średnie), 0 krytycznych |
| 7 | **Logi live** | otwórz, „Wstrzymaj” | strumień zdarzeń `SENSOR` i `ALERT`; zdarzenia triggera z etykietą `WERYFIKACJA`. Pasek „AI: wyłączone” (bramka/analiza AI nie działa na demo) |
| 8 | **Sensory** | otwórz | lista sensorów z oznaczeniem offline (lokalnie 104/114 online w pierwszej sekundzie) |
| 9 | **Cele i import** | zobacz „Dodaj cel ręcznie”, „Import pliku” | formularze są widoczne, ale jako `viewer` zapis daje 403 (zweryfikowane). Przycisk „Edytuj” przy wpisie też jest widoczny, serwer go odrzuca. Dodawanie i edycja: konto `admin` albo `editor` |
| 10 | **Reguły** | otwórz | odczyt reguł triage; zmiana wymaga uprawnienia `rules:write` |
| – | **Ustawienia**, **Role** | – | dla `viewer` zakładki są ukryte (to jest rozgraniczenie ról); administrator zobaczy ustawienia i edytor ról |

Rozgraniczenie ról pokaż na żywo: zaloguj się jako `jury`, spróbuj dodać cel (403), potem jako `admin` dodaj cel, zaimportuj plik,
edytuj wpis i zobacz zakładkę „Role” (cztery wbudowane role plus własne).

### Scenariusz dla administratora (po stronie zespołu)

1. Zakładka **Cele i import** → „Dodaj cel ręcznie”: wpisz np. `10.0.0.9`; wpis pojawia się w tabeli (status „nowe”).
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

Oczekiwane (zmierzone przed #14): `nmap -sT -sV … --max-rate 300 --host-timeout 300s` (bez NSE i OS-detection), potem
`chunk 1/1: 1 targets, 1 up, 48.03s, ok`, `probed 4 web services`, `fingerprinted`, `done in 48.03s: 1 hosts up, 7 open ports`.
Czas dominuje `-sV` na AMQP i PostgreSQL. Od #14 skaner ma tryb `-version-mode balanced` i adaptacyjne paczki, logi mają
dodatkowe pola (powód rozmiaru paczki); nowego czasu nie mierzono. Wzbogacenie CVE: dopisz `-cve` (potrzebuje sieci do NVD i EPSS; nie uruchamiano).

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

Na koniec drukuje zdarzenia sensora i znaleziska triggera. Zatrzymanie stacku (uwaga: zatrzymuje też usługi używane przez inne sesje):

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
(lokalną instancję daje `lab/defectdojo/`); wysyłki nie wykonano.

### Krok 10. Harmonogram (CLI)

```bash
./bin/scanner schedule -window 22:00-05:00 -tz Europe/Warsaw -every daily@22:00 \
  -checkpoint state.jsonl -out results -f targets.txt -allow 10.0.0.0/16
```

Nie uruchamiano w tym przeglądzie. Opis zachowania z kodu i README: skany tylko w oknach, zamknięcie okna zatrzymuje nmap,
następne okno kontynuuje z punktu kontrolnego, wynik trafia do `results/scan-<start>.json`. **Harmonogram nie jest wpięty w UI
konsoli**; pokazuj go z terminala.

### Krok 11. Bramka AI (opcjonalnie)

```bash
make cascade50-demo     # modele + bramka + konsola; modele ~2,5 GB pobierane i weryfikowane SHA256
```

Nie uruchomiono (duże pobranie). Szczegóły: `deploy/cascade50/README.md`. Na demo online bramka jest wyłączona;
sensor łączy się z triggerem bezpośrednio (krok 5).

### Sprzątanie

```bash
docker compose -f lab/agh/upstream/docker-compose-custom-network.yml \
               -f lab/agh/traffic-custom-network.yml down
rm -f scan1.json scan2.json scan3.json scan1.csv scan.xml scan.json.out ev.jsonl jar t.csv
```
