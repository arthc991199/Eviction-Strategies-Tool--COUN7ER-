
# 🛡️ Playbook: Endpoint Hardening and Proactive Defense

## 📝 Inspiracja

Ten playbook powstał na bazie praktycznych wytycznych i katalogu standardów z:

- **LexDigital**  
  [Newsletter RODO – Lipiec 2025: Zabezpieczenie stanowisk pracy](https://www.linkedin.com/posts/lexdigital_pl_lexdigital-zabezpieczenie-stanowisk-pracy-activity-7356549203562528769-gFdf)  
  Poradnik z gotowymi przykładami standardów  
  **Autor:** [Maciej Kołodziej](https://www.linkedin.com/in/kolodziejmaciej/)  
  Strona: [lexdigital.pl](https://lexdigital.pl/)

---

## 🎯 Cel

Celem tego playbooka jest **ochrona stacji roboczych (endpointów)** przed najczęściej występującymi wektorami ataku poprzez wdrożenie skutecznych środków technicznych i organizacyjnych, z uwzględnieniem:

- phishingu (e-mail, złośliwe linki, załączniki),
- złośliwego oprogramowania (z plików lokalnych, stron WWW, urządzeń USB),
- kradzieży lub utraty urządzenia,
- lateral movement w sieci lokalnej,
- oraz wsparcia skutecznego reagowania i odzyskiwania po incydencie.

> **Wskazówka:**  
> Inspiracje i konkretne wymagania sprzętowo-proceduralne, które znajdziesz w playbooku, pochodzą z materiałów LexDigital – rekomendowanych dla osób odpowiedzialnych za compliance, bezpieczeństwo IT oraz audyty zgodności z RODO, NIS2, DORA i KRI.

---

## 🔄 Fazy zastosowania

| Faza cyberobrony             | Czy playbook wspiera? | Zakres działań |
|-----------------------------|------------------------|----------------|
| 🧱 Prewencja                 | ✅ Tak                 | Hardening, kontrola dostępu, zapobieganie atakom |
| 🚨 Reakcja na incydent       | ✅ Tak                 | Logowanie, analiza, backup, izolacja |
| 🛠️ Hardening po incydencie  | ✅ Tak                 | Retrospektywa, wdrażanie dodatkowych kontroli |
| 🎓 Edukacja i audyty        | ✅ Tak                 | Wskazówki dla zespołów SOC, inżynierów i RODO |

---

## 📌 Scenariusz zagrożeń

### 1. Phishing i otwarcie złośliwego pliku
- Technika MITRE: `T1566.001` (Spearphishing Attachment)
- CM: `CM0002`, `CM0004`, `CM0010`

### 2. Wykonanie złośliwego skryptu
- Technika: `T1059` (Command and Scripting Interpreter)
- CM: `CM0004`, `CM0012`

### 3. Infekcja przez zewnętrzne urządzenia USB
- Technika: `T1200` (Hardware Additions)
- CM: `CM0059`, `CM0004`

### 4. Kradzież komputera/laptopa
- Technika: `T1529` (Implant Theft or Device Loss)
- CM: `CM0035`

### 5. Lateral movement (np. RDP)
- Technika: `T1021.001` (Remote Services: RDP)
- CM: `CM0012`, `CM0028`

### 6. Detekcja i odzyskiwanie po ataku
- Techniki: `T1059`, `T1486`
- CM: `CM0009`, `CM0043`, `CM0062`

---

## 🧰 Zastosowane środki zaradcze (Countermeasures)

| CM ID    | Opis                                      | Faza             |
|----------|-------------------------------------------|------------------|
| CM0002   | E-mail Authentication + Filtering         | Prewencja        |
| CM0004   | Application Allowlisting                  | Prewencja        |
| CM0059   | USB Port Control                          | Prewencja        |
| CM0010   | MFA Enforcement                           | Prewencja        |
| CM0012   | Least Privilege + UAC                     | Prewencja        |
| CM0035   | Device Encryption                         | Prewencja/Hardening |
| CM0009   | Endpoint Detection (EDR)                  | Detekcja/Reakcja |
| CM0043   | Logging Configuration                     | Reakcja          |
| CM0062   | Endpoint Backup Configuration             | Reakcja/Hardening |
| CM0028   | Resetowanie haseł kont                    | Reakcja/Adaptacja |

---

## 🗂️ Format JSON (do importu w CISA Eviction Strategies Tool)

Zobacz plik `endpoint_hardening.json` w tym folderze.

---

## 👥 Dla kogo jest ten playbook?

- 👩‍💼 Specjalista ds. ochrony danych (RODO): jako punkt odniesienia do technicznych środków zabezpieczających.
- 🧑‍💻 Inżynier systemowy / IT: jako zestaw zaleceń do wdrożenia.
- 🛡️ Zespół SOC: jako baza do testów, integracji z EDR/SIEM.
- 🎓 vCISO: jako element hardeningu i symulacji tabletop.

---

## 👤 Autor i projekt

**Autor:** [Artur Markiewicz](https://www.linkedin.com/comm/mynetwork/discovery-see-all?usecase=PEOPLE_FOLLOWS&followMember=artur-markiewicz)  
📬 Mail: [m@rkiewi.cz](mailto:m@rkiewi.cz)  
📆 Wersja: 1.0 (31.07.2025)

🌐 Strona projektu: [CyberMind OS](https://powiedzcospoinformatycznemu.pl/CyberMindOS/)  
📮 Newsletter: [https://subscribepage.io/art](https://subscribepage.io/art)  
☕ Jeśli materiał był pomocny → [Postaw mi kawę](https://buycoffee.to/art)

[![Sponsoruj](https://img.shields.io/badge/wsparcie%20projektu-Sponsoruj-ff69b4?style=for-the-badge&logo=github)](https://github.com/sponsors/arthc991199)
