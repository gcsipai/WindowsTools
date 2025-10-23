# 🚀 Windows 11 25H2+ FOG Klónozás Előkészítő Szkript (DevOFALL)

**Fájlnév:** `windows11-h25-fog-def.ps1`

Ez a **v2.3 BÉTA** PowerShell 🚀 szkript célja a **Windows 11 (25H2+)** 🟦 operációs rendszer automatizált és biztonságos előkészítése a **FOG Project** 🌫️ segítségével történő klónozáshoz (Golden Image készítés). Kiemelt figyelmet fordít a BitLocker kezelésére és a kritikus **Windows 11 Build 26000+** 🟦 System ID (SID) problémák javítására.

---

## 🎯 Főbb Jellemzők (Összefoglalás)

| Ikon | Funkció | Leírás |
| :---: | :--- | :--- |
| 🛡️ | **Rendszer-Ellenőrzések** | Rendszergazdai jogosultság, PowerShell 🚀 (5.0+) és elegendő lemezterület ellenőrzése. |
| ✅ | **Kompatibilitási Teszt** | Ellenőrzi az OS verzióját (**Build 26000+**), az aktiválási állapotot és a futó virtualizációs szolgáltatásokat. |
| 🔒 | **BitLocker Kezelés** | Észleli a titkosított meghajtókat, **menti a helyreállítási kulcsot**, és interaktívan visszafejti azokat. |
| 🔑 | **SID Duplikációs Javítás** | Alkalmazza a speciális registry beállításokat (`FilterAdministratorToken=0`) a SID-ütközések elkerülésére klónozás után. |
| ⚡ | **Gyorsindítás Letiltása** | Letiltja a Gyorsindítást (`HiberbootEnabled=0`) a klónozás megbízhatóságának növelésére. |
| 📄 | **Automata Unattend.xml** | Létrehozza a válaszfájlt **`CopyProfile=true`** beállítással az adminisztrátori profil másolásához. |
| 🛑 | **Sysprep Indítás** | Végrehajtja a Sysprep `/generalize /oobe /shutdown` parancsot a FOG 🌫️ klónozásra kész állapotba hozáshoz. |
| 📝 | **Részletes Naplózás** | Minden lépést rögzít egy átfogó naplófájlba (`%TEMP%\FOG_Preparation_*.log`). |

---

## 🛠️ Követelmények és Előkészületek (Kezdőknek)

### 1. Hardver / Szoftver Követelmények

* **OS:** **Windows 11 Build 25H2+** (Buildszám: **26000 felett**) 🟦.
* **PowerShell:** **PowerShell 5.0 vagy újabb** 🚀.
* **Jogosultság:** A szkriptet **Rendszergazdaként** kell futtatni.

### 2. Kritikusan Fontos Előkészület: Audit Mód ⚠️

A klónozási folyamat, különösen a felhasználói profil beállításainak átmásolása (`CopyProfile`), **csak akkor sikeres**, ha a szkriptet **Audit Módban** futtatja:

1.  **Audit Mód Aktiválása:** A Windows telepítése (OOBE képernyő) során nyomja meg a **`CTRL` + `SHIFT` + `F3`** billentyűkombinációt.
2.  **Konfiguráció:** Minden program telepítését és testreszabást a beépített **Administrator** fiókban végezzen el.
3.  **Futtatás:** Ezt a szkriptet Audit Módban kell futtatni.

---

## 📖 Használati Útmutató

### 1. Futtatás

1.  **Másolás:** Helyezze a `windows11-h25-fog-def.ps1` fájlt a forrásgépre.
2.  **Rendszergazdaként:** Nyissa meg a **PowerShellt** 🚀 **"Futtatás rendszergazdaként"** opcióval.
3.  **Végrehajtás:**
    ```powershell
    # Szükség esetén az engedélyezés:
    Set-ExecutionPolicy RemoteSigned -Scope Process -Force
    
    # A szkript futtatása:
    .\windows11-h25-fog-def.ps1
    ```
4.  **Kövessen minden interaktív utasítást.**

### 2. Interaktív Lépések és Figyelmeztetések

| Lépés | Kérdés | Várható Válasz | Megjegyzés |
| :---: | :--- | :--- | :--- |
| **BitLocker** 🔒 | Szeretné **LETILTANI** a BitLockert (és visszafejteni)? | `i` (igen) vagy `n` (nem) | **Kockázat:** Az aktív BitLockerrel rendelkező klónozott image **használhatatlan** lesz! |
| **Sysprep** 🛑 | Biztosan folytatja a Sysprep futtatását? | `i` (igen) vagy `n` (nem) | **VISSZAFORDÍTHATATLAN:** A rendszer ezután már csak FOG klónozásra lesz alkalmas. |

### 3. Befejezés és Klónozás 💾

1.  **Sikeres Befejezés:** A szkript befejezése után a rendszer **automatikusan leáll**.
2.  **FOG Capture:** A leállított számítógépet indítsa el a hálózaton keresztül (PXE boot), és indítsa el a **FOG Capture Image** (Kép rögzítése) 🌫️ folyamatot.

---

## 🔒 Biztonsági Megjegyzések

### Unattend.xml Jelszó Kockázat

A szkript által generált `unattend.xml` fájl tartalmaz egy teszt Base64 kódolású jelszót. **Éles környezetben törölje** az alábbi sort a biztonsági kockázat minimalizálása érdekében: `<Value>UABhAHMAcwB3AG8AcgBkADEAMgAzAA==</Value>`.

### Naplófájl

Minden futtatási információ, hiba és figyelmeztetés rögzítve van:

* **Naplófájl Elérési Út:** `%TEMP%\FOG_Preparation_yyyyMMdd_HHmmss.log`
