# Silence on the Wire — prezentacja (10 slajdów)

Treść slajdów i notatki mówcy. Liczby pochodzą z kodu albo z pomiarów (źródło w `ARCHITECTURE.md` i `DEMO.md`).
Elementy z otwartych PR-ów są oznaczone; przed prezentacją zaktualizuj slajdy 4, 7, 8 i 10 o to, co zostało scalone.

---

## Slajd 1. Tytuł

**Silence on the Wire**
Pasywny sensor, który budzi aktywny skaner
Attack Surface Intelligence · HackNation 2026 · zamawiający: CBI AGH

*Notatka mówcy:* Przedstawiamy narzędzie do ciągłego discovery dużej sieci. Nazwa pochodzi od książki Michała Zalewskiego
o rekonesansie pasywnym. Plan: problem, pomysł, architektura, demo, a potem szczegóły skanera, zmian w czasie i bezpieczeństwa.

---

## Slajd 2. Problem

- Duże sieci (ponad 10 000 adresów) skanuje się okresowo: między skanami zespół jest ślepy.
- Host może odpowiadać tylko o określonej porze; jednorazowy skan nie daje pełnego obrazu.
- Same otwarte porty to za mało: ważne, **co** tam działa (panel admina, staging, CMS, stary komponent).
- Pytania z zadania: jak raportować zmianę, jak ocenić pewność wyniku, kiedy uznać host za nieaktywny?

*Notatka mówcy:* Pełny skan całej sieci co kilka godzin jest drogi i hałaśliwy, więc nikt nie robi go ciągle. Brakuje
narzędzia, które to łączy z DefectDojo. Na te trzy pytania odpowiadamy konkretnie w slajdach 6 i 7.

---

## Slajd 3. Rozwiązanie i teza

**Teza:** zamiast skanować wszystko cały czas, słuchaj ruchu i skanuj tylko tam, gdzie coś się zmieniło.

```
ruch ─► sensor ──► (edgegate) ──► trigger ──► nmap + prober HTTP + sygnatury ──► findingi / diff
```

- Sensor widzi ruch ciągle: nowy host, nowa usługa, zmieniony baner, usługa zamilkła.
- Trigger zamienia zdarzenia na celowane skany, z limitami.
- Ten sam pipeline obsługuje też klasyczny skan okresowy.

*Notatka mówcy:* Pasywny sensor nic nie wysyła do sieci, więc jest bezpieczny i tani. Aktywny skan włączamy tylko po sygnale,
a jego intensywność jest ograniczona polityką.

---

## Slajd 4. Architektura

- **sensor** (Go, libpcap, filtr BPF w jądrze: ARP, SYN/RST, nagłówki odpowiedzi HTTP) → baseline hostów/usług/banerów.
- **edgegate** (opcjonalnie): kaskada modeli oceniająca zdarzenia (`score`); zdarzenia o ciszy i zamknięciu zawsze przechodzą.
- **trigger**: debounce, cooldown, quiet, rate limit, allowlista.
- **pipeline**: `nmap -sT -sV` + prober GET + sygnatury YAML.
- **wyniki**: JSON, `scanner diff`, eksport CSV / JSON / nmap XML / DefectDojo.
- **konsola**: eskalacje, flota sensorów, logowanie.
- W PR-ach: harmonogram i adaptacyjne chunki (#14), mapa ataku (#10), CVE/EPSS (#9), Shodan/Censys (#13), importer sygnatur (#7).

*Notatka mówcy:* Komponenty są osobnymi binarkami, łączą je webhooki JSON. Bramka AI jest opcjonalna: bez niej sensor
mówi do triggera bezpośrednio. Wszystko działa w kontenerach bez uprawnień poza `CAP_NET_RAW` dla sensora.

---

## Slajd 5. Demo na żywo (laboratorium CBI AGH)

1. `docker compose … up -d` (szablon AGH `custom-network` + nasza nakładka).
2. `scanner -t 127.0.0.1 -p … -Pn -o scan1.json`: 7 otwartych portów, Gitea 0,99, panel RabbitMQ 0,95.
3. Nowa usługa → drugi skan → `scanner diff`: `+ 18787/tcp http nginx 1.31.9`.
4. Logi sensora i triggera: `service_changed`, `service_closed`, `service_back`, finding z werdyktem.
5. Eksport do DefectDojo (`-dry-run`) i konsola.

Pełny scenariusz: `documentation/DEMO.md`.

*Notatka mówcy:* Skan siedmiu portów trwał 48 s (zmierzone), głównie przez `-sV`. Pokaż diff przed i po uruchomieniu
dodatkowego kontenera, potem na żywo logi sensora. Jeśli sieć zawiedzie: nagrane wyjścia są w DEMO.md.

---

## Slajd 6. Skaner i fingerprinting

- Skan: IP, CIDR (do /12), nazwy; chunki (domyślnie 256 celów) i 4 równoległe procesy nmap; czasy chunków w wyniku.
- Prober tylko GET: status, tytuł, nagłówki, ciasteczka, certyfikat TLS, przekierowania w obrębie hosta, favicon (mmh3 jak Shodan).
- 38 wbudowanych sygnatur YAML; własne przez `-signatures`.
- **Pewność:** noisy-OR wag dowodów, `1 − Π(1 − w)`; próg domyślnie 0,5.
- Obserwacje: panel administracyjny, staging, strona domyślna, instalator, certyfikat samopodpisany/wygasły.

*Notatka mówcy:* Sygnatury wykrywają obecność, nigdy nie próbują się logować ani eksploatować. Własny format łączy wyniki nmap,
odpowiedź HTTP, favicon i bezpieczne ścieżki w jednym wyniku. Kilka niezależnych słabych dowodów daje wysoką pewność,
pojedynczy słaby zostaje niski. Importer sygnatur Wappalyzer/nuclei jest w PR #7.

---

## Slajd 7. Zmiany w czasie i hosty niestabilne

- Diff dwóch skanów: nowe `+`, znikające `-`, zmienione `~` (produkt, wersja, tytuł, nagłówki, certyfikat, technologie).
- Host spoza celów nowego skanu to „nie skanowany”, nie „zniknął”.
- **Kiedy host nieaktywny?** Trzy stopnie:
  1. sensor: cisza dłuższa niż `-silent-after` (domyślnie 2 min, w labie 60 s) + przegląd co 10 s → `host_silent`;
  2. trigger weryfikuje aktywnie (top-100 portów): `still-up` albo `down-confirmed`, gdy wszystkie próby wygasły;
  3. po „żyje” 30 min ignorowania kolejnych „zamilkł”, cooldown 60 s na cel.
- Host niestabilny (flapper 60 s up / 60 s down): `service_closed` ↔ `service_back`, każda zmiana to celowany skan.
- Harmonogram i okna czasowe: PR #14. Wizualizacja w czasie: PR #10.

*Notatka mówcy:* Pojedyncza brakująca odpowiedź to nie dowód. Rozdzielamy podejrzenie od potwierdzenia. Uczciwie: w trybie
okresowym `scanner diff` oznacza zniknięcie po jednym skanie, a reguły „N skanów z rzędu” jeszcze nie mamy.

---

## Slajd 8. Bezpieczeństwo, RBAC i szyfrowanie

- Skaner: tylko GET, bez logowania i exploitów, bez NSE i OS-detection, `-sT` domyślnie.
- Ograniczenia: allowlista (`-allow`, w triggerze obowiązkowa), `-max-rate` 300 pkt/s na proces, limit 10 skanów/min, quiet, cooldown.
- Kontenery: użytkownik bez uprawnień; sensor tylko `CAP_NET_RAW`, skaner i trigger bez żadnych.
- Konsola: hasła PBKDF2-HMAC-SHA256 (120 000 iteracji), sesje 12 h, ciasteczko `HttpOnly`; na `main`: administrator / operator.
- **Role (administracja; dodawanie/usuwanie/modyfikacja; modyfikacja i odczyt; odczyt) i szyfrowanie w spoczynku: w toku** (osobna praca, jeszcze nie w `main`).

*Notatka mówcy:* Bezpieczeństwo skanera jest wymuszone w kodzie, nie tylko opisane. Role i szyfrowanie w spoczynku są
wymaganiami zadania; powiedz wprost, na jakim etapie są w dniu prezentacji, i zaktualizuj ten slajd po scaleniu.

---

## Slajd 9. Rynek i porównanie

| | nmap | SecureCodeBox | Wappalyzer / nuclei | **Silence on the Wire** |
|---|---|---|---|---|
| Skan aktywny | tak | orkiestracja skanerów | nuclei: własne żądania | nmap + GET, bezpieczny |
| Pasywny sensor i zdarzenia | nie | nie | nie | **tak** |
| Diff między skanami | zewnętrznie (ndiff) | zależnie od skanera | nie | **tak**, wbudowany |
| Własne sygnatury bez eksploatacji | NSE | szablony | tak | **tak**, tylko GET |
| DefectDojo | import XML | tak | nie | **tak**, finding informacyjny |

*Notatka mówcy:* Treść zadania wymienia SecureCodeBox jako podobny projekt, który nie spełnia w pełni wymagań. Nasz wkład
to pętla pasywny sensor → celowany skan. Kolumny dla cudzych narzędzi to nasza ogólna ocena z ich dokumentacji, nie
pomiar: sprawdź je przed prezentacją.

---

## Slajd 10. Podsumowanie i dalsze kroki

**Działa na `main`:** discovery i identyfikacja usług, fingerprinting z confidence, diff, sensor + trigger, eksport CSV/JSON/nmap/DefectDojo, konsola z logowaniem, laboratorium AGH.

**W toku / w PR-ach:** harmonogram i okna (#14), mapa ataku (#10), CVE/EPSS (#9), Shodan/Censys (#13), importer sygnatur (#7), domknięcie pętli sensor → skaner (#6), formularz importu i edycja, pełne role, szyfrowanie w spoczynku.

**Dalej:** reguła „N skanów z rzędu” dla hostów nieaktywnych, analiza zależna od pory dnia, baza danych zamiast plików JSON, pomiar na ponad 10 000 adresów.

*Notatka mówcy:* Zamknij tym, co faktycznie jest, a co w drodze. Zaproś do rozmowy o wdrożeniu w CBI AGH i współpracy
z innymi uczelniami. Przed prezentacją przejrzyj listę PR-ów i przenieś pozycje do „Działa na `main`”.
