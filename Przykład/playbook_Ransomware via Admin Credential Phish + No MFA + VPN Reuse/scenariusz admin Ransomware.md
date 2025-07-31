# 📌 Scenariusz ransomware: kompromitacja konta admina przez phishing

## 🔥 Przebieg incydentu

1. **Phishing mail do administratora** – fałszywe powiadomienie o problemie z hasłem do konta.  
2. **Podanie danych** – administrator otwiera spreparowany link i wprowadza login/hasło.  
3. **Brak MFA** – konto admina ma pełne uprawnienia w środowisku Microsoft 365 i Azure. Nie ma wymuszonego uwierzytelniania wieloskładnikowego.  
4. **Te same dane do VPN** – z lenistwa te same dane używane były do logowania przez VPN – również bez MFA.  
5. **Zdalne przejęcie organizacji**:
   - Atakujący uzyskują dostęp do infrastruktury lokalnej i chmurowej.
   - Dochodzi do zaszyfrowania lub wyłączenia:
     - Serwerów produkcyjnych,
     - Środowiska wirtualizacyjnego,
     - Systemu ERP,
     - Zapór sieciowych i backupów.

## 🛠️ Częściowe odzyskanie danych:
- Z plików użytkowników M365  
- Z backupu lokalnego (częściowo)

---

## 🧠 Uzasadnienie mapowania technik do kontrdziałań

| Technika        | Opis                                                   | Countermeasure (CM)                       |
|-----------------|--------------------------------------------------------|-------------------------------------------|
| `T1566.002`     | Spearphishing via link (login page)                    | `CM0002` – Filtrowanie i uwierzytelnianie maili |
| `T1078`         | Użycie legalnych kont po przejęciu M365/VPN           | `CM0063`, `CM0065`                         |
| `T1021.001`     | Zdalny dostęp przez VPN                                | `CM0065`                                   |
| `T1486`         | Szyfrowanie danych                                     | `CM0065` – Izolacja, by ograniczyć zasięg |
| `T1556.006`     | Brak MFA / omijanie MFA                                | ❌ Brak CM (należy dodać!)                |
| `T1110.003`     | Password Spraying, reuse haseł                         | `CM0028` – Reset haseł kont usługowych     |

---

## 📝 Uwagi
- Scenariusz może być bazą do testów tabletop lub ćwiczeń dla SOC.
- Zaleca się skorelować z realnymi politykami MFA i rotacją haseł.
- Warto rozważyć dodanie własnych CM dla MFA i segmentacji.
