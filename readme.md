# 📘 Instrukcja: Jak korzystać z Eviction Strategies Tool od CISA

**Eviction Strategies Tool** to darmowe narzędzie od amerykańskiej agencji **CISA**, stworzone w ramach frameworku **COUN7ER**.  
Pomaga zespołom bezpieczeństwa, SOC oraz vCISO w **szybkim reagowaniu na incydenty** i **usuwaniu przeciwnika z zaatakowanego środowiska**.

To **nie jest** narzędzie do wykrywania ataków – to **biblioteka gotowych działań (playbooków)**: co zrobić, gdy _coś się wydarzyło_ lub jak przygotować się wcześniej.

🔗 Narzędzie online: https://www.cisa.gov/eviction-strategies-tool/review-playbook  
📦 Repozytorium z przykładami: 

1. Scenariusz ransomware: kompromitacja konta admina przez phishing https://github.com/arthc991199/Eviction-Strategies-Tool--COUN7ER-/tree/main/Przykład/playbook_Ransomware%20via%20Admin%20Credential%20Phish%20%2B%20No%20MFA%20%2B%20VPN%20Reuse

2. Endpoint Hardening and Proactive Defense https://github.com/arthc991199/Eviction-Strategies-Tool--COUN7ER-/tree/main/Przykład/playbook_endpoint_hardening

---

## 🛡️ Co robi to narzędzie?

Działa jak **interaktywny kreator playbooków**:

- wybierasz technikę ataku (np. phishing, brute force),
- otrzymujesz gotowe **środki zaradcze** (countermeasures),
- eksportujesz plan działania jako `.json`, `.docx`, `.xlsx` lub `.md`.

Przykładowe countermeasures:
- `CM0028`: Resetowanie haseł kont usługowych  
- `CM0063`: Analiza podejrzanych logowań  
- `CM0065`: Izolacja urządzeń  
- `CM0002`: Filtrowanie załączników i uwierzytelnianie maili

---

## 🧠 Kiedy stosować?

| 📌 Faza cyberobrony             | 🎯 Czy narzędzie pomaga? | 🔧 Rola vCISO / SOC                                  |
|---------------------------------|---------------------------|-----------------------------------------------------|
| 🔍 Detekcja / przewidywanie     | ❌ Nie                    | Nie używać – to nie system wykrywania              |
| 🚨 Reagowanie na incydent       | ✅ Tak!                  | Dobór działań, mapowanie MITRE do kontrdziałań     |
| 🧩 Hardening / poprawki         | ✅ Tak                   | Lista luk i działań po ataku                        |
| 🧪 Symulacje / ćwiczenia        | ✅ Tak                   | Tworzenie playbooków, ocena przygotowania zespołu  |
| 🎓 Edukacja zespołu             | ✅ Tak                   | Nauka przez scenariusze, testowanie gotowości      |

---

## 🧭 Uwzględnianie technik MITRE ATT&CK (TTP)

Eviction Strategies Tool opiera się na taksonomii MITRE ATT&CK. W narzędziu każda countermeasure (CM) jest przypisana do konkretnych technik ataku (TTP).  
Dzięki temu możliwe jest:

- zbudowanie playbooka szytego na miarę technik użytych w ataku,
- szybkie odnalezienie luk w obecnych procedurach,
- dokumentowanie planów działania powiązanych z TTP.

📚 Baza MITRE ATT&CK: https://attack.mitre.org/

---

## 📍 Przykład scenariusza ataku

🧨 Administrator podaje dane logowania w spreparowanym mailu phishingowym.  
🛑 Brak MFA. Te same dane służą do logowania do VPN.  
💀 Przeciwnik przejmuje M365, wirtualizator, backupy, sieć.

🎯 Countermeasures:
- `CM0002`: Filtrowanie i uwierzytelnianie maili (przed atakiem)
- `CM0063`: Analiza logowań (po incydencie)
- `CM0065`: Izolacja urządzeń
- `CM0028`: Reset haseł kont usługowych

Szczegóły scenariusza w pliku: `scenario.md`

---

## 🔄 Czy CM działa przed, czy po ataku?

| Typ środka zaradczego | Opis | Przykłady |
|------------------------|------|-----------|
| **Prewencyjny**        | Działa tylko _przed_ atakiem | CM0002, CM0004, CM0059 |
| **Reakcyjny**          | Działa tylko _po_ incydencie | CM0063, CM0065, CM0028 |
| **Adaptowalny**        | Może być użyty _przed i po_ | CM0009, CM0035 |

---

## 🧪 3 dodatkowe scenariusze ransomware

### 1. 🎣 Phishing z załącznikiem
- **Techniki**: `T1566.001`, `T1059`, `T1486`
- **CM**: CM0002, CM0065, CM0063

### 2. 🔐 Brute-force i lateral movement
- **Techniki**: `T1110.003`, `T1021.002`, `T1210`
- **CM**: CM0028, CM0063, CM0065

### 3. 🌐 Exploit w aplikacji webowej
- **Techniki**: `T1190`, `T1059.003`, `T1486`
- **CM**: CM0065, CM0063

---

## 💾 Przykładowy plik JSON do importu

```json
{
  "title": "Ransomware via Admin Credential Phish + No MFA + VPN Reuse",
  "version": 1,
  "spec_version": "2.0.0",
  "tech_to_items": {
    "T1566.002": {
      "confidence": "confirmed",
      "items": [{ "id": "CM0002", "version": "1.0" }]
    },
    "T1078": {
      "confidence": "confirmed",
      "items": [
        { "id": "CM0063", "version": "1.0" },
        { "id": "CM0065", "version": "1.0" }
      ]
    },
    "T1486": {
      "confidence": "confirmed",
      "items": [{ "id": "CM0065", "version": "1.0" }]
    },
    "unmapped": {
      "confidence": "confirmed",
      "items": [{ "id": "CM0059", "version": "1.0" }]
    }
  }
}
```

➡️ **Wklej ten JSON na stronie:**  
https://www.cisa.gov/eviction-strategies-tool/review-playbook

---

## ⚙️ Wymagania techniczne

- Obsługa przez przeglądarkę (Chrome, Firefox, Edge)
- Eksport/import w formacie **COUN7ER JSON** (`spec_version: 2.0.0`)
- Rekomendowana znajomość **MITRE ATT&CK** i podstawowych technik IR

---

## 🔌 Możliwości rozbudowy i integracji

- Integracja z **SIEM / SOAR** (np. eksport CM do systemów reagowania)
- Tworzenie **własnych CM** lub rozszerzanie katalogu
- Mapowanie do **NIST CSF**, **ISO 27001** lub TTP z realnych incydentów
- Użycie jako baza do ćwiczeń **tabletop** i szkoleniowych

---

## 📚 Słownik pojęć

| Skrót / pojęcie   | Znaczenie                                               |
|-------------------|----------------------------------------------------------|
| **CM (Countermeasure)** | Środek zaradczy, np. reset konta, izolacja hosta       |
| **MITRE ATT&CK**       | Klasyfikacja technik ataku (np. phishing, brute force) |
| **MFA**                | Multi-Factor Authentication – logowanie z drugą warstwą |
| **EDR**                | Endpoint Detection & Response – monitorowanie punktów końcowych |
| **vCISO**              | Doradczy Chief Information Security Officer          |
| **SOC**                | Security Operations Center – zespół reagowania       |
| **Playbook**           | Gotowy plan działania na wypadek incydentu           |

---

## 🧭 Wnioski końcowe

- To narzędzie **nie przewiduje** ataków.
- **Nie zastępuje** SIEM, EDR ani threat intelligence.
- **Działa najlepiej po ataku** – ale im wcześniej je wdrożysz, tym skuteczniej zadziała.

---

### 🟢 Rekomendacja dla zespołu SOC i vCISO

Zintegrujcie narzędzie z Waszymi scenariuszami IR, wykonajcie testowe wdrożenie i przetestujcie zespół.  
**Eviction Strategies Tool** jest:

- ✅ darmowe,  
- ✅ aktualne,  
- ✅ zgodne z MITRE ATT&CK,  
- ✅ i uczy dobrych praktyk operacyjnych.

📌 Warto mieć je pod ręką — zanim będzie potrzebne.

---

## 👤 Autor i projekt

**Autor:** [Artur Markiewicz](https://www.linkedin.com/comm/mynetwork/discovery-see-all?usecase=PEOPLE_FOLLOWS&followMember=artur-markiewicz)  
📬 Mail: [m@rkiewi.cz](mailto:m@rkiewi.cz)  
📆 Wersja: 1.0 (30.07.2025)

🌐 Strona projektu: [CyberMind OS](https://powiedzcospoinformatycznemu.pl/CyberMindOS/)  
📮 Newsletter: [https://subscribepage.io/art](https://subscribepage.io/art)  
☕ Jeśli materiał był pomocny → [Postaw mi kawę](https://buycoffee.to/art)

[![Sponsoruj](https://img.shields.io/badge/wsparcie%20projektu-Sponsoruj-ff69b4?style=for-the-badge&logo=github)](https://github.com/sponsors/arthc991199)
