# Ściąga dla mówcy (1 strona)

Cel: 8–10 minut, 10 slajdów (`docs/slides/silence-on-the-wire.pdf`), demo na żywo na slajdzie 5. Szczegóły kroków: `DEMO.md`.

## Przed wejściem (2 minuty)

- [ ] Otwórz `https://silent.zjadlabymciastko.net` w dwóch kartach: jedna zalogowana jako `jury`, druga jako `admin`. Hasła od zespołu (nie ma ich w repo; leżą na VM w `/opt/silent-demo/secrets/`).
- [ ] Sprawdź nagłówek konsoli: „DANE DEMO” i „LIVE · tylko edge”, sensory online, w Mapie widać hosty `172.29.10.x` / `172.29.11.x`.
- [ ] Zakładka TLS ma 3 znaleziska (wygasły, wygasa za 9 dni, self-signed). Jeśli jest pusta: `admin` → „Uruchom kontrolę teraz” (dane pojawiają się po skanie kontrolnym cichych hostów).
- [ ] Terminal z repo gotowy: `make build`, w drugim oknie lab AGH (jeśli pokazujesz skan i diff lokalnie, `DEMO.md` sekcja B).
- [ ] Zapasowy plan: PDF slajdów i nagrane wyjścia w `DEMO.md`, jeśli zawiedzie sieć.

## Przebieg (czas · slajd · co powiedzieć)

| Min | Slajd | Powiedz |
|---|---|---|
| 0:00 | 1 Tytuł | Narzędzie do ciągłego discovery dużej sieci; nazwa od książki Zalewskiego o rekonesansie pasywnym. |
| 0:30 | 2 Problem | Sieci >10 000 adresów skanuje się okresowo, więc między skanami jesteśmy ślepi. Trzy pytania z zadania: jak raportować zmianę, jak ocenić pewność, kiedy host jest nieaktywny. |
| 1:15 | 3 Teza | Nie skanuj wszystkiego: słuchaj ruchu pasywnym sensorem i skanuj celowanie tam, gdzie coś się zmieniło. Sensor nic nie wysyła do sieci. |
| 2:00 | 4 Architektura | Osobne binarki połączone webhookami JSON: sensor, trigger, pipeline (nmap + GET + sygnatury), konsola, eksport do DefectDojo. Bramka AI opcjonalna, na demo wyłączona. |
| 3:00 | 5 Demo | **Na żywo, patrz niżej.** |
| 6:00 | 6 Skaner | Prober tylko GET, 38 sygnatur, pewność jako noisy-OR (`1 − Π(1 − w)`); Gitea 0,99, RabbitMQ 0,95 zmierzone na labie AGH. |
| 6:45 | 7 Zmiany w czasie | Diff `+ − ~`. Host nieaktywny w trzech stopniach: cisza sensora, aktywna weryfikacja triggera, cooldown. Flapper pokazuje hosta niestabilnego. |
| 7:30 | 8 Bezpieczeństwo | Skaner bez logowania i exploitów, allowlista, limity; RBAC (4 role + własne), AES-256-GCM. **Powiedz o lukach** (zob. niżej). |
| 8:30 | 9 Rynek | SecureCodeBox z treści zadania: orkiestruje skanery; nasz wkład to pętla sensor → skan → konsola. Kolumny cudzych narzędzi to nasza ocena, nie pomiar. |
| 9:15 | 10 Podsumowanie | Co działa, uczciwe luki, dalsze kroki; zaproś do rozmowy o wdrożeniu w CBI AGH. |

## Demo na żywo (3 minuty, slajd 5)

1. **Jako `jury`:** Alerty (liczniki, otwórz kartę sprawy) → **Mapa** (przesuń suwak czasu; flapper przełącza `service_closed` ↔ `service_back`; hosty z labu AGH z prawdziwych zdarzeń).
2. **TLS:** trzy znaleziska z certyfikatów zebranych skanami kontrolnymi; **Ryzyko:** hosty `.52` i `.51` na szczycie rankingu przez znaleziska TLS (czynniki widać w kolumnie).
3. **Role na żywo:** jako `jury` w „Cele i import” dodaj cel → **403**; przełącz kartę na `admin`, dodaj cel i zaimportuj plik → diff i edycja wpisu (edycja zostaje po ponownym imporcie).
4. **Terminal (opcjonalnie):** `scanner diff scan1.json scan2.json` (np. `+ 18787/tcp http nginx 1.31.9`) i `scanner export -format defectdojo -dry-run` (kroki 4 i 9 w `DEMO.md`).

Powiedz wprost: flota 137 sensorów i większość spraw to dane syntetyczne trybu demo; Mapę, TLS, Zasoby i zdarzenia triggera napełnia prawdziwy lab AGH.

## Uczciwe luki (mów je sam, zanim zapyta jury)

- Harmonogram (okna, częstotliwość, wznawianie) i eksport wyników są w CLI, **nie w UI konsoli**; konsola nie uruchamia skanów.
- Skala >10 000 adresów: kod jest (paczki, równoległość), **pomiaru nie robiliśmy**.
- Wyniki w plikach JSON (szyfrowane przez konsolę), nie w bazie danych; pliki wyjściowe CLI są jawne.
- Ekspozycja (Shodan/Censys) bez kluczy: pusta; bramka AI wyłączona na demo.
- Brak reguły „N skanów z rzędu” dla nieaktywności i analizy zależnej od pory dnia.
- Pełna tabela zgodności z treścią zadania: `COMPLIANCE.md`.

## Pułapki na demo

- **Zasoby:** hosty z samym portem 22 (np. bramki `172.29.10.1`, `172.29.11.1`) mają klasę „Serwer Git” z pewnością 98%; to nietrafna klasyfikacja, nie pokazuj tej zakładki jako przykładu jakości, a jeśli ktoś zapyta, powiedz, że to heurystyka na portach i jest do poprawy.
- **Mapa:** host `172.29.10.4` jest „nieosiągalny” (flapper); to zamierzony host niestabilny.
- **Dostęp:** demo jest publiczne do 16:00 (Cloudflare Access wyłączony na czas oceny), potem trzeba przywrócić Access.

## Możliwe pytania i krótkie odpowiedzi

| Pytanie | Odpowiedź |
|---|---|
| Po jakim czasie host jest nieaktywny? | Sensor: cisza dłuższa niż `-silent-after` (domyślnie 2 min) → `host_silent`; trigger weryfikuje aktywnie; „down-confirmed” dopiero po nieudanych próbach. Dla skanów okresowych reguły „N skanów” nie mamy. |
| Skąd pewność technologii? | Wagi dowodów (nagłówek, ciasteczko, HTML, favicon, ścieżka GET) łączone noisy-OR; próg 0,5. |
| Czy to bezpieczne dla skanowanej sieci? | Tylko GET, bez logowania i NSE, allowlista, `-max-rate`, limit skanów na minutę, cooldown; trigger skanuje tylko to, co jest na allowliście. |
| Jak to się integruje z DefectDojo? | `scanner export -format defectdojo` tworzy findingi informacyjne; sprawdzone `-dry-run`, bez żywej instancji. |
| Co z danymi wrażliwymi? | AES-256-GCM dla kont, ról, spraw, inwentarza, TLS, audytu; klucz poza repozytorium. Pliki wyjściowe CLI jawne (0600). |
| Dlaczego pasywny sensor? | Skan okresowy jest ślepy między przebiegami; sensor widzi zmianę od razu i budzi skan celowany. Nie wysyła nic do sieci. |
