# Zgodność z treścią zadania — audyt kodu na `main`

Audyt wykonany 2026-11-22 na `main` po PR #28 (commit `e60e087`). Metoda: każdy wiersz sprawdzono w kodzie (`git grep`) albo
uruchomieniem: `go build ./...`, `go test ./...` (wszystkie pakiety przechodzą), `scanner -h`/`schedule -h`/`export -h`,
`sensor -h`, `trigger -h`, `console -h`, lokalny skan z diffem i eksportem (CSV, nmap XML, DefectDojo `-dry-run`), lokalna
konsola `-demo` z czterema kontami (`admin`, `editor`, `analyst`, `viewer`) i macierzą wywołań API, import listy i skanów,
odczyt nagłówków plików (`ASIE`). Dokumentacji (`ARCHITECTURE.md`) nie przyjmowano na wiarę.

Czego **nie** sprawdzono: publicznego adresu (Cloudflare Access z PIN-em), wysyłki do żywego DefectDojo, bramki AI (modele ~2,5 GB),
`scanner schedule` na żywo, liczby ~60 000 sygnatur z importera (wymaga pobrania Wappalyzera i nuclei), działania na ponad 10 000 adresów.

Legenda: **jest** = działa i sprawdzone; **częściowo** = działa z zastrzeżeniem w kolumnie dowodu; **brak** = nie ma w `main`.

## 1. Wymagania z sekcji 2 treści zadania

| # | Wymaganie | Dowód w kodzie / uruchomieniu | Status |
|---|---|---|---|
| 1 | Wczytanie IP, CIDR, domen | CLI `-t`, `-f` (`cmd/scanner/main.go`, `internal/scan/targets.go`; CIDR do /12 = `MaxExpand` 1<<20, większe: błąd — sprawdzone `-t 10.0.0.0/8`). Konsola: `POST /api/targets`, `POST /api/import?kind=targets` (TXT/CSV/JSON, limit 5 MiB `maxImportBytes`; sprawdzone: CSV 4 pozycje → 2 dodane, 1 duplikat, 1 odrzucona z numerem) | jest |
| 2a | Wielowątkowy skan nmap | `-parallel` (domyślnie 4 procesy), paczki w `internal/scan` | jest |
| 2b | Czas trwania skanu | `duration` skanu i paczek w JSON, log `done in …` (sprawdzone), harmonogram loguje przewidywany koniec | jest |
| 2c | Podział adresów na podgrupy wg szybkości | `-chunk-time` (domyślnie 1 min, `-chunk-min` 4, `-chunk-max` 4096), `-chunk N` stałe | jest |
| 3 | Wykrycie aktywnych hostów | stan `up`, `-Pn`, `Host.Responded()` (`internal/result/result.go`) | jest |
| 4 | Identyfikacja podstawowych usług | `nmap -sV`, `-version-mode balanced/fast/full`, CPE | jest |
| 5 | HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | `internal/probe/probe.go` (tylko GET; przekierowania w obrębie hosta, maks. 5; treść 512 KiB) | jest |
| 6 | Technologie: CMS, framework, serwer, IoT | `internal/fingerprint/signatures/*.yaml`: **38** sygnatur (apps 11, servers 10, services 8, environment 5, iot 4); noisy-OR confidence; `cmd/sigimport` | jest (bez pomiaru trafności na zbiorze organizatorów) |
| 7 | Staging, panel administracyjny | sygnatury `environment.yaml`, tagi `staging`, `admin-panel`, `setup-page`, `default-page` (potwierdzone na labie AGH w `DEMO.md`) | jest |
| 8 | Porównanie wyników między przebiegami | `scanner diff` (`-json`, `-exit-code` — sprawdzone, kod wyjścia 1 przy różnicy), diff przy imporcie skanu w konsoli (`GET /api/inventory`, `diff_summary`) | jest |
| 9 | Nowe, znikające, zmienione usługi | `+` / `-` / `~` w `internal/diff`; sprawdzone: usługa zatrzymana między skanami → `1 gone services` | jest |
| 10 | Własne sygnatury | `-signatures plik.yaml` (skaner i trigger), `KnownFields`, importer Wappalyzer/nuclei | częściowo: tylko pliki YAML, **nie ma edytora sygnatur w UI** |
| 11 | Formularz wprowadzania danych (ręcznie + CSV/JSON), dane przetwarzane tak samo | Konsola, zakładka „Cele i import”: formularz, import listy celów i wyniku skanu; dane trafiają do inwentarza z diffem | **częściowo**: konsola **nie uruchamia skanu** wpisanych celów, więc dane z formularza nie przechodzą „tego samego” discovery/fingerprintingu, dopóki nie zeskanuje ich CLI/harmonogram/trigger i wynik nie zostanie zaimportowany |
| 12 | RBAC z możliwością tworzenia ról | `cmd/console/rbac.go` (`routePerms`, 22 uprawnienia, `POST /api/roles`, `PUT/DELETE /api/roles/{name}`) | jest |
| 13 | Role: administracja; dodawanie/usuwanie/modyfikacja; modyfikacja i odczyt; odczyt | wbudowane `admin`, `editor`, `analyst`, `viewer`. Sprawdzone macierzą wywołań (admin/editor/analyst/viewer): odczyt 200 dla wszystkich; `/api/config`, `/users`, `/roles`, `/audit` 200 tylko admin; zapis celów, import, `exposure/run`, `tls/run`, `groundtruth/run`, `PUT /api/rules` 200 admin i editor, 403 analyst i viewer; `PUT /api/overrides` 200 admin, editor, analyst, 403 viewer | jest |
| 14 | Edycja wprowadzonych wartości niezależnie od stanu skanu i zachowanie przy kolejnych skanach | `PUT /api/overrides/{key}` (tytuł, technologia, tagi, notatka, status) trzymane osobno od danych skanu (`cmd/console/overrides.go`); ponowny import skanu nie kasuje (sprawdzone) | **częściowo**: edytować można tylko nadpisania wpisów; nie można zmienić pól usługi (port, produkt, wersja), wartości celu ani konfiguracji skanu |
| 15 | Czytelny interfejs dla każdej roli i dashboard najważniejszych znalezisk | `cmd/console/static/index.html`: Alerty (liczniki i karty), Mapa, Ekspozycja, TLS, Zasoby, Ryzyko, Logi live, Sensory, Cele i import, Reguły; zakładki Ustawienia/Role ukryte dla roli bez uprawnień | jest (ocena „czytelności” subiektywna; część widoków na demo pokazuje dane syntetyczne) |
| 16 | Baza danych z szyfrowaniem w spoczynku dla pól wrażliwych | `internal/atrest` (AES-256-GCM, nagłówek `ASIE\x01`, nazwa pliku jako AAD), `cmd/console/crypt.go`; sprawdzone: `users.json` i `inventory/scan.json` zaczynają się od `ASIE` | **częściowo**: nie ma bazy danych (pliki JSON szyfrowane aplikacyjnie); `scan.json` i `findings.jsonl` zapisywane przez CLI/trigger są jawne (0600); klucz domyślnie leży obok danych (`<data-dir>/data.key`) |

Opis wielowątkowego skanu z limitem tempa i oknami (końcowy akapit sekcji 2): `-max-rate` (300 pkt/s na proces), `-host-timeout`
5 min, `scanner schedule -window … -every … -tz … -checkpoint` (zamknięcie okna zatrzymuje nmap, następne okno kontynuuje z punktu
kontrolnego, `internal/schedule`) — **jest w CLI, brak w UI konsoli**.

## 2. Minimalny zakres funkcjonalny (sekcja 3)

| Wymaganie | Dowód | Status |
|---|---|---|
| Import listy hostów/zakresów | jak 1 | jest |
| Import wyników skanów JSON/CSV | `POST /api/import?kind=scan` (JSON modelu `internal/result`, CSV ze `scanner export`); sprawdzone JSON | jest (format własny; formatu referencyjnego organizatorów nie mieliśmy) |
| Duże zakresy >10 000 IP | rozwijanie do 2^20 adresów, adaptacyjne paczki, `-parallel` | **częściowo: kod jest, skali nie zmierzono** |
| Okno czasowe i częstotliwość | `scanner schedule` (`-window`, `-every`: `once`, `24h`, `daily@22:00`, `mon+thu@22:00`) | częściowo: tylko CLI |
| Ograniczanie tempa zapytań | `-max-rate`, `-parallel`, `-probe-parallel`; trigger: `-max-per-minute` 10, `-cooldown` 60 s, `-parallel` 2 | jest |
| Wykrywanie aktywnych hostów, identyfikacja usług | jak 3–4 | jest |
| Zapis wyników do bazy lub pliku | JSON (`-o`), `findings.jsonl`; konsola: pliki szyfrowane | jest (pliki) |
| Porównanie dwóch skanów | jak 8 | jest |
| Dashboard lub raport zmian | `scanner diff`, kafelek „Ostatni diff”, Mapa z osią czasu, Alerty | jest |
| Eksport JSON/CSV | `scanner export -format csv\|json\|nmap` (sprawdzone CSV i nmap XML); konsola: tylko `GET /api/targets.txt` | częściowo: tylko CLI, w UI nie ma przycisku eksportu wyników |
| Rozgraniczenie na role | jak 12–13 | jest |
| Edycja danych istniejących skanów, wyników i konfiguracji | jak 14; konfiguracja konsoli (`/api/config`) edytowalna, **konfiguracji skanu** (okna, tempo) w UI nie ma | częściowo |
| Ochrona danych skanów (szyfrowanie) | jak 16 | częściowo (konsola tak, wyjście CLI nie) |

## 3. Dodatkowy zakres („mile widziany”)

| Pozycja | Dowód | Status |
|---|---|---|
| Harmonogram cyklicznych skanów | `scanner schedule` | jest w CLI, brak w UI |
| Różnice zależne od pory dnia | tylko stałe okna harmonogramu; brak analizy „ta sama godzina, różne dni” | **brak** |
| Ocena „ciekawości” / priorytetu | `internal/riskscore` (0–100, jawne czynniki, progi 70/40/15), CVE/EPSS/KEV (`-cve`), `score` bramki AI; konsola: zakładka Ryzyko | jest |
| Powtarzanie pomiarów dla hostów niestabilnych | trigger: `verify-host`/`verify-service`, `VerifyBackoff` 30 min, cooldown; ground truth konsoli co 6 h; **brak reguły „N skanów z rzędu” w trybie okresowym** (`scanner diff` oznacza zniknięcie po jednym skanie) | częściowo |
| Moduł HTTP/HTTPS fingerprinting | `internal/probe`, favicon mmh3 | jest |
| Proste wykrywanie CMS/technologii | jak 6 | jest |
| Grupowanie podobnych usług | kategorie i tagi sygnatur, selektory eksportu `category:`, `tag:`, `tech:`; klasy urządzeń (16) w „Zasobach” | częściowo (brak widoku grupującego w UI) |
| Obsługa tagów | tagi sygnatur, tagi użytkownika w nadpisaniach i przy imporcie celów, tagi findingów DefectDojo | jest |
| Eksport do DefectDojo jako finding informacyjny | `internal/export/defectdojo`, `scanner export -format defectdojo` (`-dry-run` sprawdzone; testy z `httptest`), stabilny `unique_id_from_tool` | jest w CLI; **wysyłki do żywej instancji nie sprawdzono**; konsola nie eksportuje |
| Wizualizacja zmian w czasie | Mapa z suwakiem czasu (dziennik topologii), monitor TLS | jest (wymaga żywego sensora) |
| Integracja z pasywnymi źródłami | własny sensor pasywny (`cmd/sensor`), ekspozycja Shodan/Censys (wymaga kluczy) | jest |

## 4. Wymagania formalne (sekcja 4) i techniczne (5)

| Wymaganie | Dowód | Status |
|---|---|---|
| Repozytorium kodu | `Inner-Savages/silence-on-the-wire`, CI buduje 5 obrazów (`sensor`, `traffic`, `scanner`, `trigger`, `console`) | jest |
| Dokumentacja techniczna | `README.md`, `docs/ARCHITECTURE.md`, `docs/DEMO.md`, `deploy/demo/README.md`, `lab/*/README.md` | jest |
| Prezentacja do 10 slajdów z demo | `docs/slides/deck.md` (10 slajdów) i `silence-on-the-wire.pdf` z notatkami; demo: `https://silent.zjadlabymciastko.net` (adresu nie sprawdzono) lub lokalnie wg `DEMO.md` | jest |
| Technologie (Go, niskie zużycie zasobów) | Go 1.26; sensor libpcap | jest |

## 5. Kryteria testowe organizatorów (sekcja 6) — ocena gotowości

| Kryterium | Ocena |
|---|---|
| Aktywne hosty, usługi, fingerprint HTTP/HTTPS, CMS/technologie, nagłówki i ciasteczka | pokryte; trafność zmierzona tylko na labie `custom-network` AGH (siedem usług). Pozostałe szablony organizatorów (`modern`, `modern-proxy`, `vulnerable`) leżą w `lab/agh/upstream/`, ale nie były skanowane w tej dokumentacji |
| Customowe sygnatury | działają (plik YAML); przykładowych sygnatur organizatorów (zasób 7.5) w repo nie ma |
| Porównanie wyników, dwa przebiegi | działa (`scanner diff`, import w konsoli) |
| Hosty niestabilne | flapper w labie, werdykty `verify-*`; patrz luka w punkcie 3 |
| Bezpieczeństwo skanera | tylko GET, bez NSE i OS-detection, allowlista, limity tempa |
| Import/export | własny format JSON/CSV; formatu referencyjnego organizatorów (zasób 7.6) w repo nie ma, więc zgodności z nim nie sprawdzono |
| Role | macierz 4 ról sprawdzona |

## 6. Najważniejsze luki (uczciwie, od najpoważniejszej)

1. **Formularz nie uruchamia skanu (wymaganie 11).** Konsola przechowuje i porównuje cele oraz zaimportowane wyniki, ale ich nie skanuje.
   Dane wpisane ręcznie nie przechodzą discovery i fingerprintingu, dopóki ktoś nie uruchomi `scanner`/`scanner schedule`/triggera.
   Z tego samego powodu harmonogram, okna i częstotliwość są dostępne tylko z CLI, a nie z interfejsu.
2. **Brak bazy danych z szyfrowaniem w spoczynku (wymaganie 16).** Zamiast bazy są pliki JSON szyfrowane aplikacyjnie (AES-256-GCM);
   wyjście skanera i triggera (`scan.json`, `findings.jsonl`) jest jawne, a klucz domyślnie leży obok danych.
3. **Skala >10 000 adresów niezmierzona.** Rozwijanie zakresów i paczki adaptacyjne są w kodzie i w testach jednostkowych, ale nie ma pomiaru
   na dużej liczbie adresów, więc kryterium „skuteczność w dużej infrastrukturze” (30%) nie ma tu liczb.
4. **Hosty niestabilne i pora dnia.** Brak reguły „host nieaktywny po N kolejnych skanach” (diff oznacza zniknięcie po jednym) i brak analizy
   różnic zależnych od pory dnia. Częściowo kompensuje to weryfikacja zdarzeniowa (sensor + trigger).
5. **Zakres edycji i eksportu w UI.** Edytować można nadpisania (tytuł, technologia, tagi, notatka, status), nie pola usługi, wartość celu ani konfigurację
   skanu; eksport wyników (CSV/JSON/DefectDojo) tylko z CLI, wysyłka do DefectDojo nieprzetestowana na żywej instancji.

Dalsze, mniejsze: brak edytora sygnatur w UI; sesje konsoli są w pamięci (restart wylogowuje); Shodan/Censys bez kluczy puste;
bramka AI wyłączona na demo; wiele widoków demo opiera się na danych syntetycznych (flota 137 sensorów, 217 spraw).

## 7. Nieścisłości w dokumentacji znalezione i poprawione w tym przeglądzie

- `README.md`: usunięto „Work in progress”; dodano opis i sekcję szybkiego startu konsoli (RBAC, import, szyfrowanie), której w README w ogóle nie było;
  obraz `console` dodany do listy obrazów CI (README i plakietka mówiły o czterech; `make images` buduje cztery, `console` buduje CI);
  lista flag triggera uzupełniona o `-findings-url`/`-findings-token`/`-parallel`; układ pakietów uzupełniony o `vuln`, `atrest`, `classify`, `tlspolicy`,
  `exposure`, `riskscore`, `sigimport`, `edge`, `deploy`.
- `docs/ARCHITECTURE.md`: zakres PR (#1–#23 → #1–#28); klasyfikacja urządzeń ma od #28 16 klas i korzysta z danych zaimportowanego skanu
  (wcześniej: 7 klas i „głównie nieznane”); odnośnik do tego pliku.
- `docs/DEMO.md`: opis „Zasobów” zgodny z #28.
- `docs/SLIDES.md`, `docs/slides/deck.md`: zakres PR; schemat sugerował eksport do DefectDojo z konsoli — eksport jest w CLI; w liście zakładek brakowało „Ekspozycji”.
  PDF wygenerowany ponownie.
- `deploy/demo/README.md`: uprawnienia roli `viewer` (mówiono: sprawy, sensory, logi, reguły; faktycznie także cele/inwentarz/nadpisania, TLS, zasoby, ryzyko).

Sprawdzone i zgodne z kodem (bez zmian): 38 sygnatur; 22 uprawnienia; domyślne `-silent-after` 2 min, `-sweep` 10 s, `-parallel` 4 (skaner) i 2 (trigger),
`-max-rate` 300, `-chunk-time` 1 min, `-host-timeout` 5 min, `-top-ports` 100 (trigger), debounce 5 s, quiet 15 s, cooldown 60 s / 5 min, 10 skanów/min,
backoff 30 min, `MaxPending` 1000, limit CIDR /12, PBKDF2 120 000 iteracji, sesja 12 h, TTL cache NVD 7 dni i EPSS/KEV 24 h, najwyżej 5 CVE na technologię,
progi TLS 30/14/7, rejestr `ASIE`, kolumny CSV, nazwy flag `-window`/`-every`/`-tz`/`-checkpoint`.
