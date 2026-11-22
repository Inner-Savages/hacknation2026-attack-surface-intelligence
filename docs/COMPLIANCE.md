# Zgodność z treścią zadania

**W skrócie:** z 16 wymagań sekcji 2 zadania 12 jest spełnionych, 4 częściowo (10, 11, 14, 16). W zakresie minimalnym 9 z 13 pozycji
jest pełnych, 4 częściowe; w dodatkowym brakuje jednej (różnice zależne od pory dnia), dwie są częściowe. Luki zebrano w
[sekcji 6](#6-najważniejsze-luki-od-najpoważniejszej).

Stan na 2026-11-22. Każdy wiersz sprawdzono w kodzie albo uruchomieniem: `go test ./...` (wszystkie pakiety przechodzą), lokalny skan
z diffem i eksportem (CSV, nmap XML, DefectDojo `-dry-run`), `scanner schedule` w otwartym oknie, lokalna konsola `-demo` z czterema
kontami (`admin`, `editor`, `analyst`, `viewer`) i macierzą wywołań API, import list i skanów, odczyt nagłówków plików (`ASIE`).
Wysyłka do żywego DefectDojo, przerwanie skanu zamknięciem okna i skany pozostałych szablonów AGH: zapisane przebiegi w PR
[#12](https://github.com/Inner-Savages/silence-on-the-wire/pull/12) i [#14](https://github.com/Inner-Savages/silence-on-the-wire/pull/14). Nie sprawdzano ponownie: bramki AI (modele ~2,5 GB), Shodan/Censys z kluczami, liczby ~60 000 sygnatur z importera.

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
| 7 | Staging, panel administracyjny | sygnatury `environment.yaml`, tagi `staging`, `admin-panel`, `setup-page`, `default-page` (potwierdzone na labie AGH, `DEMO.md`, krok 3) | jest |
| 8 | Porównanie wyników między przebiegami | `scanner diff` (`-json`, `-exit-code` — sprawdzone, kod wyjścia 1 przy różnicy), diff przy imporcie skanu w konsoli (`GET /api/inventory`, `diff_summary`) | jest |
| 9 | Nowe, znikające, zmienione usługi | `+` / `-` / `~` w `internal/diff`; sprawdzone: usługa zatrzymana między skanami → `1 gone services` | jest |
| 10 | Własne sygnatury | `-signatures plik.yaml` (skaner i trigger), `KnownFields`, importer Wappalyzer/nuclei | częściowo: tylko pliki YAML, **nie ma edytora sygnatur w UI** |
| 11 | Formularz wprowadzania danych (ręcznie + CSV/JSON), dane przetwarzane tak samo | Konsola, zakładka „Cele i import”: formularz, import listy celów i wyniku skanu; dane trafiają do inwentarza z diffem | **częściowo**: konsola nie skanuje wpisanych celów sama; robi to CLI, harmonogram albo trigger, a wynik się importuje. Wyjątek: akcja `scan` na sprawie zleca triggerowi celowany skan (`ASI_TRIGGER_URL`) |
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
| Duże zakresy >10 000 IP | rozwijanie do 2^20 adresów, adaptacyjne paczki, `-parallel`; zmierzone: **16 384 adresy w 33,8 s** (pętla zwrotna, 2 zamknięte porty, ustawienia domyślne; `ARCHITECTURE.md`, sekcja 8) | jest; bez pomiaru w prawdziwej sieci tej wielkości |
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
| Eksport do DefectDojo jako finding informacyjny | `internal/export/defectdojo`, `scanner export -format defectdojo` (`-dry-run`, testy z `httptest`, żywy DefectDojo 3.5.202: 8 utworzonych, powtórzenie 0 nowych, [#12](https://github.com/Inner-Savages/silence-on-the-wire/pull/12)), stabilny `unique_id_from_tool` | jest w CLI; konsola nie eksportuje |
| Wizualizacja zmian w czasie | Mapa z suwakiem czasu (dziennik topologii), monitor TLS | jest |
| Integracja z pasywnymi źródłami | własny sensor pasywny (`cmd/sensor`), ekspozycja Shodan/Censys (wymaga kluczy) | jest |

## 4. Wymagania formalne (sekcja 4) i techniczne (5)

| Wymaganie | Dowód | Status |
|---|---|---|
| Repozytorium kodu | `Inner-Savages/silence-on-the-wire`, CI buduje 5 obrazów (`sensor`, `traffic`, `scanner`, `trigger`, `console`) | jest |
| Dokumentacja techniczna | `README.md`, `docs/ARCHITECTURE.md`, `docs/DEMO.md`, `deploy/demo/README.md`, `lab/*/README.md` | jest |
| Prezentacja do 10 slajdów z demo | `docs/slides/deck.md` (10 slajdów) i `silence-on-the-wire.pdf` z notatkami; demo: <https://silent.zjadlabymciastko.net> lub lokalnie wg `DEMO.md` | jest |
| Technologie (Go, niskie zużycie zasobów) | Go 1.26; sensor libpcap | jest |

## 5. Kryteria testowe organizatorów (sekcja 6) — ocena gotowości

| Kryterium | Ocena |
|---|---|
| Aktywne hosty, usługi, fingerprint HTTP/HTTPS, CMS/technologie, nagłówki i ciasteczka | pokryte; trafność pokazana na labie `custom-network` AGH (siedem usług, `DEMO.md`, krok 3); szablony `vulnerable` i `modern` też skanowano, z identycznym wynikiem w trybie `balanced` i w zwykłym `nmap -sV` ([#14](https://github.com/Inner-Savages/silence-on-the-wire/pull/14)). Szablonu `modern-proxy` nie skanowano |
| Customowe sygnatury | działają (plik YAML); przykładowych sygnatur organizatorów (zasób 7.5) w repo nie ma |
| Porównanie wyników, dwa przebiegi | działa (`scanner diff`, import w konsoli) |
| Hosty niestabilne | flapper w labie, werdykty `verify-*`; patrz luka w punkcie 3 |
| Bezpieczeństwo skanera | tylko GET, bez NSE i OS-detection, allowlista, limity tempa |
| Import/export | własny format JSON/CSV; formatu referencyjnego organizatorów (zasób 7.6) w repo nie ma, więc zgodności z nim nie sprawdzono |
| Role | macierz 4 ról sprawdzona |

## 6. Najważniejsze luki (od najpoważniejszej)

1. **Formularz nie uruchamia skanu (wymaganie 11).** Konsola przechowuje i porównuje cele oraz zaimportowane wyniki, ale ich nie skanuje.
   Dane wpisane ręcznie nie przechodzą discovery i fingerprintingu, dopóki ktoś nie uruchomi `scanner`/`scanner schedule`/triggera.
   Z tego samego powodu harmonogram, okna i częstotliwość są dostępne tylko z CLI, a nie z interfejsu.
2. **Brak bazy danych z szyfrowaniem w spoczynku (wymaganie 16).** Zamiast bazy są pliki JSON szyfrowane aplikacyjnie (AES-256-GCM);
   wyjście skanera i triggera (`scan.json`, `findings.jsonl`) jest jawne, a klucz domyślnie leży obok danych.
3. **Skala >10 000 adresów zmierzona tylko na pętli zwrotnej** (16 384 adresy, 33,8 s). Nie obejmuje opóźnień sieci, filtrowanych hostów
   ani `-sV` na tysiącach usług.
4. **Hosty niestabilne i pora dnia.** Brak reguły „host nieaktywny po N kolejnych skanach” (diff oznacza zniknięcie po jednym) i brak analizy
   różnic zależnych od pory dnia. Częściowo kompensuje to weryfikacja zdarzeniowa (sensor + trigger).
5. **Zakres edycji i eksportu w UI.** Edytować można nadpisania (tytuł, technologia, tagi, notatka, status), nie pola usługi, wartość celu ani konfigurację
   skanu; eksport wyników (CSV/JSON/DefectDojo) tylko z CLI.

Dalsze, mniejsze: brak edytora sygnatur w UI; sesje konsoli są w pamięci (restart wylogowuje); Shodan/Censys bez kluczy puste;
bramka AI wyłączona na demo; flota (137 sensorów) i większość spraw na demo
są syntetyczne, Mapa, TLS i Zasoby pochodzą z żywego labu; klasyfikacja urządzeń to heurystyka i bywa błędna dla pojedynczych hostów.
