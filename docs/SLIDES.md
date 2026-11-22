# Silence on the Wire — prezentacja (10 slajdów)

Treść slajdów i notatki mówcy. Stan: `main` po PR #1–#28 (2026-11-22). Liczby pochodzą z kodu albo z pomiarów (źródło w
`ARCHITECTURE.md` i `DEMO.md`). Luki są nazwane wprost na slajdach 8 i 10; nie ukrywaj ich w prezentacji.

---

## Slajd 1. Tytuł

**Silence on the Wire**
Pasywny sensor, który budzi aktywny skaner
Attack Surface Intelligence · HackNation 2026 · zamawiający: CBI AGH
Demo: https://silent.zjadlabymciastko.net

*Notatka mówcy:* Narzędzie do ciągłego discovery dużej sieci. Nazwa pochodzi od książki Michała Zalewskiego o rekonesansie
pasywnym. Plan: problem, pomysł, architektura, demo, a potem skaner, zmiany w czasie, bezpieczeństwo i role, rynek, podsumowanie.

---

## Slajd 2. Problem

- Duże sieci (ponad 10 000 adresów) skanuje się okresowo: między skanami zespół jest ślepy.
- Host może odpowiadać tylko o określonej porze; jednorazowy skan nie daje pełnego obrazu.
- Same otwarte porty to za mało: ważne, **co** tam działa (panel admina, staging, CMS, stary komponent) i **co z tym zrobić najpierw**.
- Pytania z zadania: jak raportować zmianę, jak ocenić pewność wyniku, kiedy uznać host za nieaktywny?

*Notatka mówcy:* Pełny skan całej sieci jest drogi i hałaśliwy, więc nikt nie robi go ciągle. Brakuje narzędzia, które to łączy
z DefectDojo. Na te trzy pytania odpowiadamy konkretnie na slajdach 6 i 7.

---

## Slajd 3. Rozwiązanie i teza

**Teza:** nie skanuj wszystkiego cały czas; słuchaj ruchu i skanuj tylko tam, gdzie coś się zmieniło.

```
ruch ─► sensor ──► (edgegate) ──► trigger ──► nmap + prober HTTP + sygnatury (+CVE/EPSS) ──► konsola (diff, ryzyko) / scanner export (CSV, DefectDojo)
```

- Sensor widzi ruch ciągle: nowy host, nowa usługa, zmieniony baner, usługa zamilkła.
- Trigger zamienia zdarzenia na celowane skany, z limitami; wynik wraca do konsoli jako sprawa z werdyktem.
- Ten sam pipeline obsługuje klasyczny skan okresowy (`scanner`, `scanner schedule`).
- Konsola: role, edycja z zachowaniem przy rescanach, szyfrowanie w spoczynku, ranking ryzyka.

*Notatka mówcy:* Pasywny sensor niczego nie wysyła do sieci, więc jest bezpieczny i tani. Aktywny skan włączamy po sygnale,
a jego intensywność ogranicza polityka.

---

## Slajd 4. Architektura

- **sensor** (Go, libpcap, filtr BPF w jądrze) → baseline hostów, usług i banerów; zdarzenia webhookiem i `POST /logs`.
- **edgegate** (opcjonalnie): kaskada modeli nadaje `score`; na demo wyłączona.
- **trigger**: debounce, cooldown, quiet, limit tempa, allowlista; wyniki do konsoli przez `POST /findings`.
- **pipeline**: `nmap -sT -sV` + prober GET + sygnatury YAML (38 wbudowanych, importer Wappalyzer/nuclei) + CVE/EPSS (`-cve`).
- **harmonogram**: okna czasowe, częstotliwość, wznawianie, adaptacyjne paczki (CLI).
- **konsola**: Alerty, Mapa, Ekspozycja, TLS, Zasoby, Ryzyko, Cele i import, Role (nie uruchamia skanów, nie eksportuje do DefectDojo: robi to CLI).
- **eksport**: CSV / JSON / nmap XML / DefectDojo.

*Notatka mówcy:* Komponenty to osobne binarki połączone webhookami JSON. Bramka AI jest opcjonalna. Wszystko działa w kontenerach
bez uprawnień poza `CAP_NET_RAW` dla sensora. Publiczne demo: jedna VM, konsola za Cloudflare Tunnel i Access, lab AGH z sensorem
i triggerem na tej samej maszynie, aktualizacja co 5 min.

---

## Slajd 5. Demo na żywo

1. Wejście na `silent.zjadlabymciastko.net`, PIN z Cloudflare Access, logowanie kontem `jury` (tylko odczyt).
2. **Alerty** (liczniki, karta sprawy) → **Mapa** (suwak czasu, flapper przełącza się między `service_closed` i `service_back`).
3. **Ryzyko**: top hostów z wynikiem 0–100 i czynnikami; **TLS**, **Zasoby**, **Ekspozycja** (bez kluczy: „nie jest skonfigurowana”).
4. Jako `jury` próba dodania celu: **403**; jako `admin`: import listy i skanu, diff, edycja wpisu, ponowny import, edycja zostaje.
5. Terminal: `scanner` + `scanner diff` (`+ 18787/tcp http nginx 1.31.9`) i `scanner export -format defectdojo -dry-run`.

Pełny scenariusz i oczekiwane wyniki: `docs/DEMO.md`.

*Notatka mówcy:* Pokaż rozgraniczenie ról na żywo: ten sam ekran, dwa konta. Uczciwie: część widoków (flota 137 sensorów, sprawy, ranking)
to dane syntetyczne trybu demo; Mapę i Zasoby napełniają prawdziwe zdarzenia z labu AGH. Jeśli sieć zawiedzie, wyniki z terminala
są w DEMO.md. Skan siedmiu portów lokalnego labu trwał 48 s (zmierzone, `-sV` na AMQP i PostgreSQL).

---

## Slajd 6. Skaner i fingerprinting

- Skan: IP, CIDR (do /12), nazwy; paczki dobierane do zmierzonego tempa (`-chunk-time`), 4 równoległe procesy nmap, czasy paczek w wyniku.
- Prober tylko GET: status, tytuł, nagłówki, ciasteczka, certyfikat TLS, przekierowania w obrębie hosta, favicon (mmh3 jak Shodan).
- 38 wbudowanych sygnatur YAML; własne przez `-signatures`; importer Wappalyzer/nuclei (README: ok. 60 000 sygnatur na obecnych źródłach).
- **Pewność:** noisy-OR wag dowodów, `1 − Π(1 − w)`; próg domyślnie 0,5. Zmierzone: Gitea 0,99, RabbitMQ Management 0,95.
- Obserwacje: panel administracyjny, staging, strona domyślna, instalator, certyfikat samopodpisany; CVE z EPSS i KEV (`-cve`).

*Notatka mówcy:* Sygnatury wykrywają obecność, nigdy nie próbują logowania ani eksploatacji. Kilka niezależnych słabych dowodów
daje wysoką pewność, pojedynczy słaby zostaje niski. Jedna rzecz do powiedzenia o CVE: zapytanie idzie do NVD i FIRST, nie do hosta,
i tylko gdy znamy wersję produktu.

---

## Slajd 7. Zmiany w czasie i hosty niestabilne

- Diff dwóch skanów: nowe `+`, znikające `-`, zmienione `~`; host spoza celów nowego skanu to „nie skanowany”, nie „zniknął”.
- Mapa powierzchni ataku odtwarza dziennik topologii suwakiem czasu; monitor TLS zgłasza wygasanie (30/14/7 dni) i zmianę CA.
- **Kiedy host nieaktywny?** Trzy stopnie:
  1. sensor: cisza dłuższa niż `-silent-after` (domyślnie 2 min, w labie 60 s) + przegląd co 10 s → `host_silent`;
  2. trigger weryfikuje aktywnie (top-100 portów): `still-up` albo `down-confirmed`, gdy wszystkie próby wygasły;
  3. po „żyje” 30 min ignorowania kolejnych „zamilkł”, cooldown 60 s na cel.
- Ground truth: co 6 h sonda próbki do 50 hostów milczących ponad 60 min.
- Host niestabilny (flapper 60 s up / 60 s down): `service_closed` ↔ `service_back`, każda zmiana to celowany skan.
- Harmonogram: okna `-window`, `-every`, wznawianie po zamknięciu okna (CLI).

*Notatka mówcy:* Pojedyncza brakująca odpowiedź to nie dowód. Rozdzielamy podejrzenie od potwierdzenia. Uczciwie: w trybie okresowym
`scanner diff` oznacza zniknięcie po jednym skanie; reguły „N skanów z rzędu” nie mamy. Analizy „ta sama pora, różne dni” też nie.

---

## Slajd 8. Bezpieczeństwo, RBAC i szyfrowanie

- Skaner: tylko GET, bez logowania i exploitów, bez NSE i OS-detection, `-sT` domyślnie; allowlista, `-max-rate` 300 pkt/s na proces, 10 skanów/min w triggerze.
- Kontenery: użytkownik bez uprawnień; sensor tylko `CAP_NET_RAW`, skaner i trigger bez żadnych.
- **RBAC** na uprawnieniach (22), cztery role: `admin` (administracja), `editor` (dodawanie, usuwanie, modyfikacja), `analyst` (modyfikacja i odczyt), `viewer` (odczyt) + własne role z edytora; audyt zmian.
- **Szyfrowanie w spoczynku:** AES-256-GCM dla kont, ról, ustawień, spraw, inwentarza, TLS i audytu; klucz poza repozytorium.
- Hasła PBKDF2-HMAC-SHA256 (120 000 iteracji), samorejestracja wyłączona, demo za Cloudflare Access.
- **Luki:** pliki wyjściowe CLI (`scan.json`, `findings.jsonl`) nie są szyfrowane; harmonogram i uruchamianie skanu nie są w UI konsoli.

*Notatka mówcy:* Pokaż, że `jury` dostaje 403 na zapisie, mimo że przycisk „Edytuj” jest widoczny (serwer jest źródłem prawdy). Szyfrowanie
sprawdzone: pliki zaczynają się od nagłówka `ASIE`. Powiedz wprost o lukach.

---

## Slajd 9. Rynek i porównanie

| | nmap | SecureCodeBox | Wappalyzer / nuclei | **Silence on the Wire** |
|---|---|---|---|---|
| Skan aktywny | tak | orkiestracja skanerów | nuclei: własne żądania | nmap + GET, bezpieczny |
| Pasywny sensor i zdarzenia | nie | nie | nie | **tak** |
| Diff między skanami | zewnętrznie (ndiff) | zależnie od skanera | nie | **tak**, wbudowany |
| Własne sygnatury bez eksploatacji | NSE | szablony | tak | **tak**, tylko GET, plus importer ich baz |
| DefectDojo | import XML | tak | nie | **tak**, finding informacyjny |
| RBAC, szyfrowanie, ranking ryzyka | nie | nie | nie | **tak** (konsola) |

*Notatka mówcy:* Treść zadania wymienia SecureCodeBox jako podobny projekt, który nie spełnia w pełni wymagań. Nasz wkład to pętla
pasywny sensor → celowany skan → konsola z rolami. Kolumny dla cudzych narzędzi to nasza ogólna ocena z dokumentacji, nie pomiar:
sprawdź je przed prezentacją.

---

## Slajd 10. Podsumowanie i dalsze kroki

**Działa na `main`:** discovery i identyfikacja usług, fingerprinting z confidence, diff, sensor + trigger, eksport CSV/JSON/nmap/DefectDojo,
harmonogram i adaptacyjne paczki (CLI), CVE/EPSS, importer sygnatur, konsola z RBAC (4 role + własne), szyfrowaniem AES-GCM, importem i edycją,
mapą, TLS, zasobami i rankingiem ryzyka, wdrożenie demo.

**Luki (uczciwie):** harmonogram i uruchamianie skanu poza UI konsoli; Shodan/Censys bez kluczy puste; bramka AI wyłączona na demo; brak
reguły „N skanów z rzędu” i analizy pory dnia; skala >10 000 adresów niezmierzona; pliki wyjściowe CLI nieszyfrowane; wyniki w plikach, nie w bazie.

**Dalej:** harmonogram i skan z konsoli, baza z szyfrowaniem, pomiar na ponad 10 000 adresów, klucze Shodan/Censys, wdrożenie w CBI AGH.

*Notatka mówcy:* Zamknij tym, co faktycznie jest, i tym, co w drodze. Zaproś do rozmowy o wdrożeniu w CBI AGH i współpracy
z innymi uczelniami.
