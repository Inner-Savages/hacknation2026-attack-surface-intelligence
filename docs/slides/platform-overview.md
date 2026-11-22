---
marp: true
theme: default
paginate: true
size: 16:9
title: Silence on the Wire
description: Attack Surface Intelligence, HackNation 2026 (CBI AGH)
style: |
  :root { --g:#0f9d6e; --ink:#1b2430; --mut:#5d6b7a; --bg:#ffffff; --soft:#f1f5f4; --warn:#c2410c; }
  section { font-family: "Inter","Helvetica Neue",Arial,sans-serif; color:var(--ink); background:var(--bg);
            padding:56px 70px 60px; font-size:26px; line-height:1.38; }
  section::after { color:var(--mut); font-size:16px; }
  h1 { font-size:54px; color:var(--ink); margin:0 0 .2em; letter-spacing:-.5px; }
  h2 { font-size:38px; color:var(--ink); border-left:10px solid var(--g); padding-left:16px; margin:0 0 .6em; }
  h3 { font-size:28px; color:var(--ink); margin:.4em 0 .2em; }
  strong { color:var(--g); }
  ul { margin:.2em 0; padding-left:1.1em; } li { margin:.28em 0; }
  code { background:var(--soft); color:var(--ink); padding:.05em .3em; border-radius:5px; font-size:.86em; }
  pre { background:var(--soft); border-radius:10px; padding:.7em 1em; font-size:21px; }
  table { font-size:21px; border-collapse:collapse; width:100%; }
  th { background:var(--ink); color:#fff; padding:.35em .5em; text-align:left; }
  td { padding:.32em .5em; border-bottom:1px solid #dfe6e4; }
  .lead { color:var(--mut); font-size:30px; }
  .small { font-size:20px; color:var(--mut); }
  .warn { color:var(--warn); }
  .flow { display:flex; align-items:center; gap:10px; margin:.7em 0 .9em; font-size:20px; }
  .box { background:var(--soft); border:2px solid var(--g); border-radius:12px; padding:.5em .7em; text-align:center; flex:1; }
  .box b { display:block; color:var(--g); font-size:22px; }
  .box.opt { border-style:dashed; border-color:#9aa8a4; }
  .arrow { color:var(--g); font-size:30px; }
  .cols { display:grid; grid-template-columns:1fr 1fr; gap:34px; }
  .kpi { display:flex; gap:18px; margin:.5em 0; } .kpi div { flex:1; background:var(--soft); border-radius:12px; padding:.5em .7em; text-align:center; font-size:20px; color:var(--mut); }
  .kpi b { display:block; font-size:40px; color:var(--g); }
  section.title { background:linear-gradient(135deg,#0b2a22 0%,#12493a 100%); color:#fff; justify-content:center; }
  section.title h1 { color:#fff; font-size:76px; } section.title .lead { color:#b9e4d4; }
  section.title strong { color:#7ee2b8; } section.title::after { color:#b9e4d4; }
---

<!-- _class: title -->
<!-- _paginate: false -->

# Silence on the Wire

<p class="lead">Pasywny sensor, który budzi aktywny skaner</p>

**Attack Surface Intelligence** · HackNation 2026 · zamawiający: CBI AGH

<p class="small" style="color:#b9e4d4">Przegląd platformy: moduły, demo, roadmapa · appendix do decku głównego · demo: silent.zjadlabymciastko.net</p>

<!--
Appendix do decku głównego (deck.md, 10 slajdów wymaganych przez treść zadania): pełny przegląd
platformy moduł po module, screenshoty z konsoli, konta demo i roadmapa — materiał na pytania jury.
-->

---

## Problem i teza

<div class="cols">
<div>

### Problem

- Duże sieci (**10 000+ adresów**) skanuje się okresowo — między skanami zespół jest ślepy
- Host może odpowiadać tylko o określonej porze
- Same porty to za mało: liczy się, **co** tam działa i **co naprawić najpierw**

</div>
<div>

### Teza

**Słuchaj ruchu cały czas, skanuj aktywnie tylko tam, gdzie coś się zmieniło.**

- sensor pasywny = tanio i bezpiecznie, 24/7
- skan aktywny = celowany, z limitami, na żądanie zdarzenia
- konsola = jedna powierzchnia decyzyjna dla operatora

</div>
</div>

---

## Przepływ danych

<div class="flow">
  <div class="box"><b>Sensor</b>libpcap + BPF, baseline</div><span class="arrow">➜</span>
  <div class="box opt"><b>Edgegate</b>opcjonalny scoring AI</div><span class="arrow">➜</span>
  <div class="box"><b>Trigger</b>polityka, limity</div><span class="arrow">➜</span>
  <div class="box"><b>Pipeline</b>nmap + prober + sygnatury + CVE</div><span class="arrow">➜</span>
  <div class="box"><b>Konsola</b>sprawy, ryzyko, akcje</div>
</div>

- **3 tryby tego samego potoku**: ręczny (`scanner`), harmonogram (`scanner schedule`), zdarzeniowy (sensor → trigger)
- Wszystko ląduje w **konsoli operatora**: `POST /logs` (sensor), `/findings` (trigger), `/events` (bramka AI), import plików
- Osobne binarki połączone webhookami JSON z tokenem — każdy moduł da się wymienić lub wyłączyć

---

## Mapa modułów

| Warstwa | Moduły | Rola w jednym zdaniu |
|---|---|---|
| **Obserwacja** | sensor, traffic (lab) | widzi ruch i zgłasza zmiany; generator ruchu do testów |
| **Decyzja edge** | edgegate (basal, laya, kev) | kaskada modeli ML ocenia zdarzenia przed skanem |
| **Egzekucja** | trigger, scanner, schedule | zamienia zdarzenia w celowane, bezpieczne skany |
| **Wiedza** | probe, fingerprint, sigimport, vuln, diff, result, export | co tam działa, jakie CVE, co się zmieniło, eksport |
| **Konsola** | console + 14 pakietów wewn. | sprawy, mapa, ekspozycja, TLS, zasoby, ryzyko, reguły, AI operator, RBAC, audyt, szyfrowanie |

<p class="small">Go 1.26 · Python (modele ML) · ~20 pakietów w <code>internal/</code> · pokrycie testami publikowane jako badge z CI</p>

---

## Moduł: Sensor — oczy platformy

**Co robi:** przechwytuje pakiety (libpcap, filtr BPF w jądrze: ARP, SYN/RST, nagłówki HTTP), buduje trwały **baseline hostów, usług i banerów** i emituje zdarzenia JSON-lines / webhook.

| Zdarzenie | Znaczenie |
|---|---|
| `host_new`, `service_new` | coś się pojawiło |
| `service_changed` | zmienił się odcisk banera HTTP |
| `service_closed` | RST: host żyje, port zamknięty |
| `host_silent`, `service_silent` | cisza dłużej niż `-silent-after` (2 min) |
| `host_back`, `service_back` | powrót po ciszy/zamknięciu |

<p class="small">Tylko <code>CAP_NET_RAW</code> · wykluczenia własnej infrastruktury (<code>-exclude-net</code>, globs interfejsów) · TTL+checkpoint historii hostów (skala 10k IP) · replay z pcap do testów</p>

---

## Moduł: Edgegate — kaskada AI na krawędzi

**Co robi:** opcjonalna bramka między sensorem a triggerem. Kaskada **Tree+GNB → Basal + Laya + Kev** ocenia każde zdarzenie i przekazuje dalej z polem `score`; zdarzenia o ciszy/zamknięciu przechodzą zawsze.

- **Standard wymienności:** modele wystawiają wspólny interfejs HTTP (`/v1/systemone`) — wraz z rozwojem AI przepinamy się na nowsze, mniejsze, tańsze energetycznie modele bez zmian w reszcie systemu
- Wagi (~2,5 GB) pobierane z przypiętych rewizji i weryfikowane **SHA256** — nie leżą w repo
- Może działać na **zewnętrznym kontenerze**, gdy endpoint nie udźwignie modeli

<p class="small">Cel 50% odfiltrowania skalibrowany na danych syntetycznych — to nie twarda kwota. W demo online bramka wyłączona.</p>

---

## Moduł: Trigger — bezpiecznik aktywnej strony

**Co robi:** zamienia zdarzenia w **celowane zlecenia skanu** przez ten sam pipeline; wynik jako *finding* z werdyktem i diffem względem poprzedniego skanu celu, wysyłany do konsoli.

<div class="cols">
<div>

**Polityka (czysta, testowalna):**

- allowlista **wymagana**, ignorowanie własnych adresów
- debounce 5 s, quiet 15 s, cooldown 60 s / 5 min
- limit 10 skanów/min, 1000 zleceń, 2 równolegle

</div>
<div>

**Werdykty findingów:**

`scanned` · `still-open` · `gone-confirmed` · `still-up` · `down-confirmed` · `error`

Histereza: po „żyje" ignoruje „zamilkł" przez 30 min — skan sam budzi hosta.

</div>
</div>

<p class="small"><code>GET /healthz</code> pokazuje kolejkę i powody odrzuceń · <code>-findings-url</code> wysyła findingi do konsoli z tokenem</p>

---

## Moduł: Skaner i harmonogram

<div class="cols">
<div>

### Skaner (`cmd/scanner`)

- cele: IP, CIDR do /12, domeny; pliki TXT
- paczki **adaptacyjne** (`-chunk-time`) po równoległe procesy nmap
- bezpieczny profil: `-sT` connect, `-sV`, limit 300 pkt/s, **bez NSE i OS detection**
- `scanner diff`: `+` nowe, `-` znikające, `~` zmienione

</div>
<div>

### Harmonogram (`scanner schedule`)

- okna czasowe (`-window`), częstotliwość (`-every`), strefa (`-tz`)
- zamknięcie okna zatrzymuje nmap, kolejne okno **kontynuuje** od checkpointu
- paczki liczone tak, by zdążyć przed końcem okna

</div>
</div>

<p class="small">Wynik = jeden dokument JSON z ustawieniami i czasami paczek — skan jest odtwarzalny.</p>

---

## Moduł: Prober, sygnatury i importer

**Prober (`internal/probe`):** wyłącznie GET — status, tytuł, nagłówki, ciasteczka, przekierowania w obrębie hosta, **certyfikat TLS**, favicon (hash **mmh3 zgodny z Shodan**).

**Sygnatury (`internal/fingerprint`):** własny format YAML, jeden rodzaj dowodu na matcher, wagi → **noisy-OR confidence**. 38 wbudowanych (CMS, panele, bazy, IoT, staging, admin-panel…).

**Importer (`cmd/sigimport`):** tłumaczy Wappalyzer i szablony nuclei (w tym hashe favicon) na nasz YAML → **~60 000 sygnatur** bez adopcji ich silników. Generowany plik to dane — przerabia się go z nowych źródeł.

<p class="small">Favicon: admin ukryje Server, wersję i tytuł — stockowej ikonki prawie nikt nie podmienia.</p>

---

## Moduł: CVE / EPSS / KEV

**Co robi:** wykrytą wersję produktu tłumaczy na **CPE**, pyta **NVD** o CVE i szereguje je wg prawdopodobieństwa eksploatacji **EPSS** (FIRST), oznaczając listę **CISA KEV**.

- Każda technologia w wyniku: do 5 pozycji `CVE-… — CVSS, EPSS, KEV`
- Bez wersji **celowo nie pytamy** — odpytanie bez wersji to szum, nie wywiad
- Fail-soft: brak sieci = brak wzbogacenia; cache na dysku (NVD 7 dni, EPSS/KEV 24 h)
- `NVD_API_KEY` podnosi anonimowy limit ~10×

<p class="small">Zmienia listę zmian w <strong>ranking realnego ryzyka</strong> — serce attack surface intelligence.</p>

---

## Moduł: Diff i eksport

- **Diff (`internal/diff`):** nowe / znikające / zmienione hosty i usługi; pomija dane zmienne z natury (daty, ETag); host spoza celów nowego skanu to „nie skanowany", nie „zniknął"; ostrzega przy różnicy argumentów nmap
- **Eksport (`scanner export`):** CSV, JSON, nmap XML i **DefectDojo** — obserwacje (panel admina, staging, self-signed, przeterminowane komponenty) jako findingi informacyjne ze stabilnym `unique_id_from_tool` (kolejne przebiegi odświeżają dowody, nie ruszają decyzji analityka)
- Selektory: `-select default,category:database,tech:Gitea,tag:login`, `-min-confidence`

---

## Konsola operatora — jedna powierzchnia decyzyjna

| Zakładka | Co daje |
|---|---|
| **Alerty** | sprawy z licznikami, statusy, notatki, **akcje** (skan, odcięcie z potwierdzeniem) |
| **Mapa** | topologia sieci z **suwakiem czasu** — widać dryf powierzchni |
| **Ekspozycja** | diff „wnętrze vs internet" (Shodan/Censys) — shadow IT |
| **TLS** | wygasanie 30/14/7 dni, self-signed, zmiana CA, słaba kryptografia |
| **Zasoby** | żywy CMDB z ruchu: 16 klas urządzeń (kamera, drukarka, IoT…) |
| **Ryzyko** | ranking hostów 0–100 z jawnym rozbiciem na czynniki |
| **Logi live / Sensory** | strumień zdarzeń na żywo, flota i jej kondycja |
| **Cele i import** | formularz + import TXT/CSV/JSON z diffem, nadpisania przeżywają skany |
| **Reguły / Ustawienia / Role** | tryb deterministyczny, AI operator, RBAC |

---

## Alerty — triage spraw na żywo

![h:540](img/platform/alerty.png)

---

## Sprawa: oceny kaskady ML i audytowane akcje

![h:540](img/platform/sprawa.png)

---

## Ranking ryzyka i logi na żywo

<div class="cols">
<div>

![w:100%](img/platform/ryzyko.png)

</div>
<div>

![w:100%](img/platform/logi.png)

</div>
</div>

---

## Konsola: bezpieczeństwo samej platformy

<div class="cols">
<div>

### RBAC i audyt

- **22 uprawnienia**, role wbudowane: `admin`, `editor`, `analyst`, `viewer` + role własne
- PBKDF2 (120k iteracji), sesje 12 h, `HttpOnly`+`SameSite=Lax`
- samorejestracja do wyłączenia (`ASI_ALLOW_REGISTRATION=false`)
- każda zmiana sprawy/roli/konta w **dzienniku audytu**

</div>
<div>

### Szyfrowanie w spoczynku

- **AES-256-GCM**, nagłówek `ASIE\x01`, nazwa pliku jako AAD
- szyfrowane: konta, role, ustawienia (z kluczami API), sprawy, inwentarz, TLS, ekspozycja, audyt
- klucz z env/pliku/pierwszego startu (0600); utrata klucza = nieczytelne dane

</div>
</div>

---

## Konsola: AI operator i tryb reguł

<div class="cols">
<div>

### AI operator (LLM)

- analiza logów z endpointów przez **dowolne API zgodne z OpenAI** — ChatGPT, ale też model lokalny; klucz w ustawieniach konta (`ASI_AI_API_KEY`)
- orkiestruje pracą platformy: ocenia ruch, zmienia statusy spraw, **uzbraja** akcje
- **odcięcie hosta zawsze potwierdza człowiek** — pełny audyt decyzji AI

</div>
<div>

### Tryb reguł (fallback)

- gdy modele decyzyjne (Bayes, drzewa, basal/kev…) są zbyt wolne: przełącznik na **sztywne reguły** definiowane w dashboardzie
- reguły startowe w repo; triage deterministyczne bez ML

</div>
</div>

<p class="small">Tryb demo z syntetyczną flotą ↔ przełącznik na prawdziwe logi z sensorów edge — jeden przycisk.</p>

---

## Moduł: Ground truth — kontrola ślepego scenariusza

**Problem:** host, który nigdy nic nie wysyła (`silent_stealth`), jest pasywnie nierozróżnialny od wyłączonego.

**Rozwiązanie:** co 6 h konsola sonduje próbkę (50) hostów milczących ≥ 60 min łączeniami TCP na znanych portach.

- werdykt **„zweryfikowany cichy"** vs **„ZMIANA w ciszy"** trafia na mapę i do spraw
- luka obserwowalności jest **mierzona**, nie niewidoczna

<p class="small">Ustawienia w dashboardzie: interwał, próg ciszy, wielkość próbki.</p>

---

## Bezpieczeństwo działania (defensywność)

- Skaner i prober **tylko odczyt**: GET bez logowania, przekierowania w obrębie hosta, limity rozmiaru i czasu
- Limity tempa wszędzie: `-max-rate`, `-parallel`, cooldowny, quiet window, cap kolejki
- Allowlista celów wymagana w triggerze; CIDR max /12
- Kontenery **bez uprawnień** (`cap_drop: ALL`; sensor tylko `CAP_NET_RAW`)
- Webhooki z tokenem bearer; bez tokena 401
- Zapytania CVE/EPSS idą do NVD/FIRST — **nigdy** do skanowanych hostów

---

## Wdrożenie i CI

- **5 obrazów** (sensor, scanner, trigger, traffic, console) z CI na ghcr.io, amd64+arm64, tagi `latest`/`sha`/`semver`
- Testy z pokryciem + badge; budowanie obrazów także na PR
- **Demo publiczne**: jedna VM, konsola za **Cloudflare Tunnel + Access** (PIN na e-mail), zero publikowanych portów, aktualizacja obrazów co 5 min
- **Stack cascade50**: konsola + edgegate + modele ML (basal/laya/kev) + central — compose
- **Lab CBI AGH**: nakładka dodaje sensor, trigger, traffic i hosta „flapper" bez ruszania ich szablonów

---

## Konta do publicznego demo

| Login | Rola | Co wolno |
|---|---|---|
| `jury` | viewer | pełny podgląd wszystkich zakładek, zero zapisu — niczego nie da się zepsuć |
| `jury-analyst` | analyst | podgląd + triage spraw: statusy, notatki, nadpisania |
| `admin` | administracja | **pokażemy w finale** 😄 |

<p class="small">Wejście przez Cloudflare Access (jednorazowy PIN na e-mail) · hasła kont w secrets na VM, nie w repo · samorejestracja wyłączona</p>

---

## Roadmapa

<div class="cols">
<div>

### Krótki termin

- harmonogram i przycisk skanu w UI konsoli
- eksport CSV/JSON/DefectDojo z poziomu sprawy
- pomiar skali 10k+ i strojenie paczek
- menu nawigacji jako dropdown (PR #31), fix obrazu konsoli cascade50 (PR #33)

### Średni termin

- prawdziwe wykonanie odcięcia hosta (integracja z firewall/SDN, dziś audytowana decyzja)
- konto usługowe i SSO/OIDC
- baza SQL dla wyników zamiast plików

</div>
<div>

### Długi termin

- **federacja sensorów** — setki edge'ów, hierarchiczne agregowanie
- akcje SOAR: playbooki (odciecie → monitoring → przywrócenie) z audytem
- nowe klasy modeli edge przez standardowy interfejs — mniejsze, tańsze energetycznie
- korelacja „pora dnia × dzień tygodnia" dla hostów okresowych
- edytor sygnatur i marketplace reguł w UI

</div>
</div>

---

<!-- _class: title -->
<!-- _paginate: false -->

# Podsumowanie

<p class="lead">Sensor słucha. Trigger decyduje. Skaner sprawdza. Konsola daje operatorowi pełny obraz i audytowane akcje.</p>

**repo:** github.com/Inner-Savages/silence-on-the-wire · **demo:** silent.zjadlabymciastko.net
