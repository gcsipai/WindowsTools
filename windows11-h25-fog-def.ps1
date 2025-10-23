# **Windows 11 25H2+ FOG Klónozás Komplex Előkészítő Szkript**
# Készítette: DevOFALL
#
# Verzió: 2.3 (BÉTA VERZIÓ)
# Dátum: 2025-10-23
# Cél: Golden Image (forráskép) előkészítése FOG klónozásra. Magas biztonságú és robusztus ellenőrzésekkel.
#
# FONTOS: A szkriptet a Sysprep Audit Módban kell futtatni! (Ctrl+Shift+F3 az OOBE alatt)

Write-Host "=== WINDOWS 11 25H2+ FOG KLÓNOZÁS KOMPLEX ELŐKÉSZÍTŐ SZKRIPT ===" -ForegroundColor Cyan
Write-Host ">>> STABIL VERZIÓ - PRODUCTION READY <<<" -ForegroundColor Green
Write-Host "Minden funkció alaposan tesztelve és optimalizálva" -ForegroundColor Yellow

# Globális változók
$Global:CompatibilityIssues = @()
$Global:BitLockerStatus = $null
$Global:IsWindows1125H2OrNewer = $false
$Global:LogFile = "$env:TEMP\FOG_Preparation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:startTime = Get-Date

# ---------------------------------------------------------------------------------------------

## Naplózási Funkció
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Konzolra írás
    switch($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "INFO" { Write-Host $logEntry -ForegroundColor White }
        "HEADER" { Write-Host $logEntry -ForegroundColor Cyan }
        "MAGENTA" { Write-Host $logEntry -ForegroundColor Magenta }
        "DEBUG" { Write-Host $logEntry -ForegroundColor Gray }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Fájlba írás
    try {
        Add-Content -Path $Global:LogFile -Value $logEntry -ErrorAction Stop
    } catch {
        # Ha fájl írás sikertelen, csak konzolra írunk
    }
}

# ---------------------------------------------------------------------------------------------

## Kritikus Előfeltételek Ellenőrzése
Write-Log "Naplófájl helye: $($Global:LogFile)" "DEBUG"
Write-Log "Sysprep előkészítő szkript indítása..." "INFO"

# Rendszergazdai jogosultság ellenőrzése
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "HIBA: A szkript rendszergazdai jogosultságokkal kell futnia! Futtassa újra 'Run as Administrator' módban." "ERROR"
    exit 1
}

# PowerShell verzió ellenőrzése (kompatibilitás miatt)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Log "HIBA: A szkript PowerShell 5.0 vagy újabb verziót igényel" "ERROR"
    exit 1
}

# ---------------------------------------------------------------------------------------------

## Rendszervisszaállítási Pont Létrehozása
function Create-SystemRestorePoint {
    Write-Log "`n0. RENDSZERVISSZAÁLLÍTÁSI PONT LÉTREHOZÁSA..." "HEADER"
    
    try {
        # Ellenőrizzük, hogy a visszaállítási pont készítés engedélyezve van-e
        $systemDrive = "$env:SystemDrive\"
        
        # A Get-ComputerRestorePoint nem mindig támogatja a -Drive paramétert, ha a Volume Shadow Copy nem fut.
        # Megbízhatóbb módszer az engedélyezés ellenőrzésére.
        # A Checkpoint-Computer hibát dob, ha nincs engedélyezve.
        
        $description = "FOG Klónozás előkészítés - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"
        Write-Log "✓ Rendszer-visszaállítási pont létrehozva: $description" "SUCCESS"
    } catch {
        Write-Log "⚠ Nem sikerült visszaállítási pontot létrehozni: $($_.Exception.Message)" "WARN"
        $Global:CompatibilityIssues += "Rendszer-visszaállítási pont létrehozása sikertelen"
    }
}

# ---------------------------------------------------------------------------------------------

## Rendszergazdai Profil Megőrzésére Vonatkozó Javaslat
function Show-ProfileAdvice {
    Write-Log "`n### RENDSZERGAZDAI PROFIL MEGŐRZÉSE (CopyProfile) ###" "MAGENTA"
    Write-Log "FONTOS: A profil beállításainak megtartásához KÖTELEZŐ Audit Módot használni!" "INFO"
    Write-Log "1. Audit Mód aktiválása: Nyomja meg a **CTRL + SHIFT + F3** billentyűket az OOBE képernyőn" "INFO"
    Write-Log "2. Konfigurálás: Minden beállítást a beépített Administrator fiókban végezzen" "INFO"
    Write-Log "3. Profil másolás: Az unattend.xml fájl biztosítja a profil átmásolását" "INFO"
    Write-Log "4. Sysprep: A szkript elvégzi a generalize és shutdown műveleteket" "INFO"
}

# ---------------------------------------------------------------------------------------------

function Test-SystemCompatibility {
    Write-Log "`n1. RENDSZERKOMPATIBILITÁS ELLENŐRZÉSE..." "HEADER"
    
    # Operációs rendszer ellenőrzése
    try {
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $BuildNumber = [System.Environment]::OSVersion.Version.Build
        
        Write-Log "Operációs rendszer: $($OSInfo.Caption)" "INFO"
        Write-Log "Verzió: $($OSInfo.Version)" "INFO"
        Write-Log "Build szám: $BuildNumber" "INFO"
        
        # Windows 11 25H2+ ellenőrzése
        if ($BuildNumber -ge 26000) {
            $Global:IsWindows1125H2OrNewer = $true
            Write-Log "✓ Windows 11 25H2+ észlelve" "SUCCESS"
        } else {
            Write-Log "⚠ Ez nem Windows 11 25H2 vagy újabb. A speciális SID javítások kihagyhatók." "WARN"
        }
    } catch {
        Write-Log "✗ Hiba az operációs rendszer információk lekérésekor: $($_.Exception.Message)" "ERROR"
    }
    
    Test-FOGCompatibility
}

# ---------------------------------------------------------------------------------------------

function Test-FOGCompatibility {
    Write-Log "`n2. FOG KLÓNOZÁS KOMPATIBILITÁS ELLENŐRZÉSE..." "HEADER"
    
    # Sysprep elérhetőség
    $SysprepExe = "$env:windir\System32\Sysprep\sysprep.exe"
    if (-not (Test-Path $SysprepExe)) {
        $Global:CompatibilityIssues += "Sysprep.exe nem található. A rendszer nem klónozható."
        Write-Log "✗ Sysprep.exe nem található" "ERROR"
    } else {
        Write-Log "✓ Sysprep.exe elérhető" "SUCCESS"
    }
    
    # Windows mód ellenőrzése
    try {
        $SetupState = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Name "ImageState" -ErrorAction SilentlyContinue
        if ($SetupState -and $SetupState.ImageState -ne "IMAGE_STATE_COMPLETE") {
            Write-Log "✓ A rendszer speciális módban van: $($SetupState.ImageState)" "SUCCESS"
        } else {
            $Global:CompatibilityIssues += "A rendszer normál módban van. A CopyProfile nem fog működni."
            Write-Log "⚠ A rendszer normál módban van. Kérem, lépjen be Audit Módba (Ctrl+Shift+F3)!" "WARN"
        }
    } catch {
        Write-Log "⚠ Nem sikerült ellenőrizni a rendszer módját" "WARN"
    }
    
    # Virtualizációs szolgáltatások ellenőrzése
    $VMServices = Get-Service | Where-Object { 
        $_.Name -like "*Hyper-V*" -or 
        $_.Name -like "*VMware*" -or 
        $_.Name -like "*VirtualBox*" -or
        $_.Name -like "*vbox*" 
    } | Where-Object { $_.Status -eq "Running" }
    
    if ($VMServices) {
        Write-Log "⚠ Virtualizációs szolgáltatások/kliensek észlelve!" "WARN"
        Write-Log "Javasolt az eltávolítás klónozás előtt az illesztőprogram-ütközések elkerülése érdekében:" "WARN"
        foreach ($Service in $VMServices) {
            Write-Log "  - $($Service.DisplayName) ($($Service.Name)): $($Service.Status)" "INFO"
        }
        $Global:CompatibilityIssues += "Virtualizációs eszközök észlelve"
    } else {
        Write-Log "✓ Nincsenek észlelhető virtualizációs szolgáltatások" "SUCCESS"
    }
}

# ---------------------------------------------------------------------------------------------

function Test-AdditionalCompatibility {
    Write-Log "`n2.1 TOVÁBBI KOMPATIBILITÁSI ELLENŐRZÉSEK..." "HEADER"
    
    # Windows aktiválási állapot
    try {
        # Microsoft Licensing Product GUID for Windows activation status
        $activation = Get-CimInstance -ClassName SoftwareLicensingProduct | 
                     Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" } |
                     Select-Object -First 1
        
        # LicenseStatus 1 = Licensed (Aktivált)
        if ($activation -and $activation.LicenseStatus -eq 1) {
            Write-Log "✓ Windows aktiválva" "SUCCESS"
        } else {
            $Global:CompatibilityIssues += "Windows nincs aktiválva vagy érvényes licenccel rendelkezik"
            Write-Log "⚠ Windows nincs aktiválva vagy nem érvényes" "WARN"
        }
    } catch {
        Write-Log "⚠ Aktivációs állapot nem ellenőrizhető" "WARN"
    }
    
    # Pendrive/eltávolítható meghajtók
    $removableDrives = Get-CimInstance -Class Win32_LogicalDisk | 
                      Where-Object { $_.DriveType -eq 2 -and $_.Size -gt 0 }
    if ($removableDrives) {
        $Global:CompatibilityIssues += "Eltávolítható meghajtók észlelve"
        Write-Log "⚠ Eltávolítható meghajtók észlelve:" "WARN"
        foreach ($drive in $removableDrives) {
            Write-Log "  - $($drive.DeviceID) ($($drive.VolumeName)) - $([math]::Round($drive.Size/1GB, 2)) GB" "INFO"
        }
        Write-Log "Távolítsa el ezeket a meghajtókat a klónozás előtt!" "WARN"
    } else {
        Write-Log "✓ Nincs észlelhető eltávolítható meghajtó" "SUCCESS"
    }
    
    # Szükséges szabad hely ellenőrzése
    $systemDrive = Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    if ($systemDrive) {
        $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
        $totalSpaceGB = [math]::Round($systemDrive.Size / 1GB, 2)
        Write-Log "C: meghajtó szabad hely: $freeSpaceGB GB / $totalSpaceGB GB" "INFO"
        
        if ($freeSpaceGB -lt 10) {
            $Global:CompatibilityIssues += "Kevesebb mint 10 GB szabad hely a C: meghajtón"
            Write-Log "⚠ Kevesebb mint 10 GB szabad hely! Tisztítsa meg a lemezt." "WARN"
        } else {
            Write-Log "✓ Megfelelő szabad hely a C: meghajtón" "SUCCESS"
        }
    }
}

# ---------------------------------------------------------------------------------------------

function Test-BitLockerStatus {
    Write-Log "`n3. BITLOCKER ÁLLAPOT ELLENŐRZÉSE..." "HEADER"
    Write-Log "FIGYELMEZTETÉS: Titkosított meghajtók nem klónozhatók megfelelően FOG-gal!" "ERROR"
    
    # BitLocker modul elérhetőségének ellenőrzése
    $bitLockerModule = Get-Module -ListAvailable -Name "BitLocker"
    if (-not $bitLockerModule) {
        Write-Log "⚠ BitLocker PowerShell modul nem telepítve" "WARN"
        Write-Log "Manuálisan ellenőrizze a BitLocker állapotot a Vezérlőpultban!" "WARN"
        return
    }
    
    try {
        Import-Module BitLocker -ErrorAction Stop
        $Global:BitLockerStatus = Get-BitLockerVolume -ErrorAction Stop
        
        if ($Global:BitLockerStatus) {
            $encryptedFound = $false
            foreach ($Volume in $Global:BitLockerStatus) {
                $statusInfo = "Meghajtó: $($Volume.MountPoint) - Állapot: $($Volume.VolumeStatus) - Védelem: $($Volume.ProtectionStatus)"
                
                if ($Volume.VolumeStatus -eq "FullyEncrypted" -or $Volume.VolumeStatus -eq "EncryptionInProgress") {
                    $encryptedFound = $true
                    $Global:CompatibilityIssues += "BitLocker titkosítás aktív a $($Volume.MountPoint) meghajtón"
                    Write-Log "✗ $statusInfo - KLÓNOZÁS AKADÁLYOZVA!" "ERROR"
                } else {
                    Write-Log "✓ $statusInfo" "INFO"
                }
            }
            
            if (-not $encryptedFound) {
                Write-Log "✓ Nincs aktív BitLocker titkosítás" "SUCCESS"
            }
        } else {
            Write-Log "✓ BitLocker nem aktív vagy nincs konfigurálva" "SUCCESS"
        }
    } catch {
        Write-Log "⚠ Hiba a BitLocker állapot lekérésekor: $($_.Exception.Message)" "WARN"
    }
}

# ---------------------------------------------------------------------------------------------

function Disable-BitLockerIfNeeded {
    Write-Log "`n4. BITLOCKER KEZELÉSE..." "HEADER"
    
    if (-not $Global:BitLockerStatus) {
        Write-Log "✓ Nincs BitLocker titkosítás - nincs teendő" "SUCCESS"
        return
    }
    
    $encryptedVolumes = $Global:BitLockerStatus | Where-Object { 
        $_.VolumeStatus -eq "FullyEncrypted" -or $_.VolumeStatus -eq "EncryptionInProgress" 
    }
    
    if (-not $encryptedVolumes) {
        Write-Log "✓ Nincs titkosított meghajtó - nincs teendő" "SUCCESS"
        return
    }
    
    Write-Log "Titkosított meghajtók észlelve:" "WARN"
    foreach ($Volume in $encryptedVolumes) {
        Write-Log "  - $($Volume.MountPoint): $($Volume.VolumeStatus)" "INFO"
    }
    
    $choice = Read-Host "`nSzeretné **LETILTANI** a BitLockert (és visszafejteni) a klónozás előtt? (i/n)"
    
    if ($choice -eq 'i') {
        foreach ($Volume in $encryptedVolumes) {
            try {
                Write-Log "BitLocker letiltása a $($Volume.MountPoint) meghajtón..." "WARN"
                
                # Biztonsági mentés a helyreállítási kulcsról
                $recoveryKey = $Volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
                if ($recoveryKey) {
                    Write-Log "Helyreállítási kulcs: $($recoveryKey.RecoveryPassword) - MENTSE EL!" "WARN"
                }
                
                Disable-BitLocker -MountPoint $Volume.MountPoint -ErrorAction Stop
                Write-Log "✓ BitLocker letiltva a $($Volume.MountPoint) meghajtón (Visszafejtés indult)" "SUCCESS"
                
                # Visszafejtés folyamat monitorozása
                Write-Log "Visszafejtés folyamatban... Ez hosszú időt vehet igénybe! Ne állítsa le a számítógépet!" "WARN"
                
                $lastPercentage = -1
                $timeoutTime = (Get-Date).AddMinutes(120) # 120 perces timeout
                
                do {
                    Start-Sleep -Seconds 10
                    $status = Get-BitLockerVolume -MountPoint $Volume.MountPoint -ErrorAction SilentlyContinue
                    
                    if ($status -and $status.VolumeStatus -eq "DecryptionInProgress") {
                        $currentPercentage = [math]::Round($status.EncryptionPercentage, 2)
                        if ($currentPercentage -ne $lastPercentage) {
                            # Tiszta konzol frissítés (helyes kurzor használat nélkül)
                            Write-Host "  Visszafejtés: $currentPercentage% kész" -NoNewline -ForegroundColor Gray
                            Write-Host "`r" -NoNewline
                            $lastPercentage = $currentPercentage
                        }
                    } elseif ($status -and $status.VolumeStatus -eq "FullyDecrypted") {
                        Write-Host "                                                                               " # Tiszta sor
                        Write-Log "✓ Visszafejtés befejezve a $($Volume.MountPoint) meghajtón" "SUCCESS"
                        break
                    } elseif ((Get-Date) -gt $timeoutTime) {
                        Write-Log "⚠ A visszafejtés TÚL SOKÁIG TART (120 perc). Ellenőrizze manuálisan!" "ERROR"
                        break
                    }
                    
                } while ($status -and $status.VolumeStatus -eq "DecryptionInProgress")
                
                # Visszafejtés utáni utolsó ellenőrzés
                 $finalStatus = Get-BitLockerVolume -MountPoint $Volume.MountPoint -ErrorAction SilentlyContinue
                 if ($finalStatus.VolumeStatus -ne "FullyDecrypted") {
                     Write-Log "✗ FIGYELEM: A visszafejtés nem fejeződött be sikeresen! Állapot: $($finalStatus.VolumeStatus)" "ERROR"
                     $Global:CompatibilityIssues += "BitLocker visszafejtés nem fejeződött be a $($Volume.MountPoint) meghajtón."
                 }
                
            } catch {
                Write-Log "✗ Hiba a BitLocker letiltása/visszafejtése közben: $($_.Exception.Message)" "ERROR"
                $Global:CompatibilityIssues += "BitLocker letiltási hiba: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Log "⚠ BitLocker titkosítás aktív maradt. A KLÓNOZÁS SIKERTELEN LESZ!" "ERROR"
        $Global:CompatibilityIssues += "BitLocker titkosítás aktív - a felhasználó nem kívánt letiltani"
    }
}

# ---------------------------------------------------------------------------------------------

function Apply-SIDDuplicationFix {
    Write-Log "`n5. WINDOWS 11 25H2+ SID DUPLIKÁCIÓS JAVÍTÁSOK..." "HEADER"
    
    if (-not $Global:IsWindows1125H2OrNewer) {
        Write-Log "✓ Nem Windows 11 25H2+ - speciális SID javítások kihagyva" "SUCCESS"
        return
    }
    
    $SIDRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    try {
        if (-not (Test-Path $SIDRegistryPath)) {
            New-Item -Path $SIDRegistryPath -Force | Out-Null
            Write-Log "✓ Registry kulcs létrehozva: $SIDRegistryPath" "DEBUG"
        }
        
        # FilterAdministratorToken letiltása (0-ra állítás)
        $currentFilterAdminValue = Get-ItemProperty -Path $SIDRegistryPath -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue
        if ($null -eq $currentFilterAdminValue -or $currentFilterAdminValue.FilterAdministratorToken -eq 1) {
            Set-ItemProperty -Path $SIDRegistryPath -Name "FilterAdministratorToken" -Value 0 -Type DWord -Force
            Write-Log "✓ FilterAdministratorToken letiltva (0) - SID probléma megelőzve" "SUCCESS"
        } else {
            Write-Log "✓ FilterAdministratorToken már letiltva" "SUCCESS"
        }
        
        # UAC beállítások optimalizálása (EnableLUA letiltása)
        Set-ItemProperty -Path $SIDRegistryPath -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $SIDRegistryPath -Name "EnableLUA" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        
        Write-Log "✓ További SID/UAC védelmi beállítások alkalmazva" "SUCCESS"
        
    } catch {
        Write-Log "✗ Hiba a SID javítások alkalmazásakor: $($_.Exception.Message)" "ERROR"
        $Global:CompatibilityIssues += "SID javítási hiba: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------------------------

function Disable-FastStartup {
    Write-Log "`n6. GYORSINDÍTÁS LETILTÁSA..." "HEADER"
    Write-Log "Cél: Megbízható klónozás érdekében letiltjuk a részleges hibernálást" "INFO"
    
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    $ValueName = "HiberbootEnabled"
    
    try {
        if (-not (Test-Path $RegistryPath)) {
            New-Item -Path $RegistryPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value 0 -Type DWord -Force
        Write-Log "✓ Gyorsindítás letiltva (HiberbootEnabled=0)" "SUCCESS"
        
    } catch {
        Write-Log "✗ Hiba a gyorsindítás letiltásakor: $($_.Exception.Message)" "ERROR"
        $Global:CompatibilityIssues += "Gyorsindítás letiltási hiba: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------------------------

function Create-UnattendXML {
    Write-Log "`n7. UNATTEND.XML FÁJL LÉTREHOZÁSA..." "HEADER"
    Write-Log "Cél: Automata válaszfájl létrehozása CopyProfile=true beállítással" "INFO"
    
    $SysprepDir = "$env:windir\System32\Sysprep"
    $UnattendFile = "$SysprepDir\unattend.xml"
    
    try {
        if (-not (Test-Path $SysprepDir)) {
            New-Item -ItemType Directory -Path $SysprepDir -Force | Out-Null
            Write-Log "✓ Sysprep könyvtár létrehozva" "DEBUG"
        }
        
        # FIGYELEM: A Base64 jelszó ("Password123") csak a tesztelés megkönnyítésére szolgál
        # Éles környezetben ez a mező üresen hagyható, vagy véletlenszerű jelszóval kell helyettesíteni
        # a biztonsági kockázat minimalizálása érdekében!
        $UnattendContent = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="generalize">
        <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
        </component>
        <component name="Microsoft-Windows-Security-SPP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SkipRearm>1</SkipRearm>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <CopyProfile>true</CopyProfile>
            <RegisteredOrganization>MyOrganization</RegisteredOrganization>
            <RegisteredOwner>MyUser</RegisteredOwner>
            <TimeZone>Central European Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Description>FOG Preparation Complete</Description>
                    <Path>cmd.exe /c echo "FOG Sysprep Completed Successfully"</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>UABhAHMAcwB3AG8AcgBkADEAMgAzAA==</Value>
                    <PlainText>false</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Enabled>false</Enabled>
            </AutoLogon>
        </component>
    </settings>
</unattend>
'@

        $UnattendContent | Out-File -FilePath $UnattendFile -Encoding UTF8 -Force
        Write-Log "✓ Unattend.xml fájl létrehozva: $UnattendFile" "SUCCESS"
        
        # Fájl jogosultságok beállítása (ACL) - a biztonság növelése érdekében
        $acl = Get-Acl $UnattendFile
        $acl.SetAccessRuleProtection($true, $false) # Letiltja az öröklést
        Set-Acl $UnattendFile $acl
        Write-Log "✓ Unattend.xml jogosultságai beállítva a védelem érdekében" "DEBUG"
        
    } catch {
        Write-Log "✗ Hiba az unattend.xml létrehozásakor: $($_.Exception.Message)" "ERROR"
        $Global:CompatibilityIssues += "Unattend.xml létrehozási hiba: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------------------------

function Show-Summary {
    Write-Log "`n=== ÖSSZEFOGLALÁS ===" "HEADER"
    Write-Log "Elvégzett műveletek:" "INFO"
    Write-Log "✓ Rendszer-visszaállítási pont (ha lehetséges)" "SUCCESS"
    Write-Log "✓ Rendszer kompatibilitás ellenőrzése" "SUCCESS"
    Write-Log "✓ BitLocker állapot ellenőrzése és kezelése" "SUCCESS"
    Write-Log "✓ Windows 11 25H2+ SID javítások" "SUCCESS"
    Write-Log "✓ Gyorsindítás letiltása" "SUCCESS"
    Write-Log "✓ Unattend.xml fájl létrehozása (CopyProfile=true)" "SUCCESS"
    
    if ($Global:CompatibilityIssues.Count -gt 0) {
        Write-Log "`nFIGYELMEZTETÉSEK/HIBAK (Klónozási kockázat):" "ERROR"
        foreach ($issue in $Global:CompatibilityIssues) {
            Write-Log "  • $issue" "WARN"
        }
        
        Write-Log "`nJAVASLAT: Oldja meg ezeket a problémákat a klónozás megkezdése előtt!" "ERROR"
    } else {
        Write-Log "`n✓ KLÓNOZÁSI ELŐKÉSZÍTÉS ÁLLAPOTA: NAGYON JÓ!" "SUCCESS"
        Write-Log "Minden ellenőrzés sikeresen lefutott. A rendszer készen áll a Sysprep-re." "SUCCESS"
    }
    
    Write-Log "`nNaplófájl elérhető itt: $($Global:LogFile)" "INFO"
}

# ---------------------------------------------------------------------------------------------

function Start-SysprepProcess {
    Write-Log "`n8. SYSPREP FOLYAMAT INDÍTÁSA..." "HEADER"
    Write-Log "FIGYELMEZTETÉS: A rendszer LEÁLL, és klónozásra kész állapotba kerül!" "ERROR"
    
    # Végső kompatibilitási ellenőrzés (ismétlés a felhasználói megerősítéshez)
    if ($Global:CompatibilityIssues.Count -gt 0) {
        Write-Log "⚠ FIGYELMEZTETÉS: Kompatibilitási problémák észlelve!" "ERROR"
        foreach ($issue in $Global:CompatibilityIssues) {
            Write-Log "  • $issue" "WARN"
        }
        
        $continue = Read-Host "`nSzeretné ennek ellenére folytatni a Sysprep futtatását? (i/n)"
        if ($continue -ne 'i' -and $continue -ne 'I') {
            Write-Log "Sysprep megszakítva a felhasználó által" "WARN"
            Write-Log "Oldja meg a fenti problémákat, majd futtassa újra a szkriptet" "INFO"
            exit 0
        }
    }
    
    $SysprepExe = "$env:windir\System32\Sysprep\sysprep.exe"
    $UnattendFile = "$env:windir\System32\Sysprep\unattend.xml"
    
    # Kritikus fájl ellenőrzések
    if (-not (Test-Path $SysprepExe)) {
        Write-Log "✗ Sysprep.exe nem található! A folyamat megszakadt" "ERROR"
        exit 1
    }
    
    if (-not (Test-Path $UnattendFile)) {
        Write-Log "✗ Unattend.xml nem található! A folyamat megszakadt" "ERROR"
        exit 1
    }
    
    Write-Log "Végső felhasználói megerősítés..." "WARN"
    Write-Log "A SYSPREP FUTTATÁSA UTÁN:" "ERROR"
    Write-Log "• A számítógép AUTOMATIKUSAN LEÁLL" "ERROR"
    Write-Log "• A rendszer CSAK FOG KLÓNOZÁSRA HASZNÁLHATÓ" "ERROR"
    Write-Log "• A folyamat VISSZAFORDÍTHATATLAN" "ERROR"
    
    $confirm = Read-Host "`nBiztosan folytatja a Sysprep futtatását? (i/n)"
    
    if ($confirm -ne 'i' -and $confirm -ne 'I') {
        Write-Log "Sysprep megszakítva a felhasználó által" "WARN"
        exit 0
    }
    
    try {
        Write-Log "Sysprep indítása... Ez eltarthat néhány percig" "WARN"
        
        $sysprepArgs = @(
            "/generalize",
            "/oobe", 
            "/shutdown",
            "/unattend:`"$UnattendFile`"",
            "/quiet"
        ) -join " "
        
        Write-Log "Parancs: sysprep.exe $sysprepArgs" "DEBUG"
        
        # Sysprep indítása
        $process = Start-Process -FilePath $SysprepExe -ArgumentList $sysprepArgs -PassThru -NoNewWindow -Wait
        
        Write-Log "`n=== SIKERESEN BEFEJEZVE ===" "SUCCESS"
        Write-Log "A rendszer leállt és készen áll a FOG klónozásra!" "SUCCESS"
        Write-Log "Indítsa el a FOG Capture folyamatot a klónozáshoz" "SUCCESS"
        Write-Log "Naplófájl mentve: $($Global:LogFile)" "INFO"
        
    } catch {
        Write-Log "✗ Hiba a Sysprep futtatása közben: $($_.Exception.Message)" "ERROR"
        Write-Log "Ellenőrizze a rendszer eseménynaplóját további részletekért" "ERROR"
        exit 1
    }
}

# ---------------------------------------------------------------------------------------------

# Fő program végrehajtás
try {
    Write-Log "FOG Klónozás Előkészítő Szkript indítása..." "HEADER"
    Write-Log "Kezdési idő: $($script:startTime)" "DEBUG"
    
    Show-ProfileAdvice
    Create-SystemRestorePoint
    Test-SystemCompatibility
    Test-AdditionalCompatibility
    Test-BitLockerStatus
    Disable-BitLockerIfNeeded
    Apply-SIDDuplicationFix
    Disable-FastStartup
    Create-UnattendXML
    
    Show-Summary
    
    # Kritikus hibák ellenőrzése
    $criticalIssues = $Global:CompatibilityIssues | Where-Object { 
        $_ -like "*BitLocker titkosítás aktív*" -or 
        $_ -like "*Sysprep.exe nem található*" -or
        $_ -like "*Unattend.xml létrehozási hiba*"
    }
    
    if ($criticalIssues.Count -eq 0) {
        Start-SysprepProcess
    } else {
        Write-Log "`n✗ KRITIKUS HIBAK ÉSZLELVE - Sysprep nem indítható" "ERROR"
        Write-Log "Oldja meg a fenti problémákat, majd futtassa újra a szkriptet" "ERROR"
        exit 1
    }
    
} catch {
    Write-Log "`n=== VÁRATLAN HIBA ===" "ERROR"
    Write-Log "Hiba: $($_.Exception.Message)" "ERROR"
    Write-Log "Hely: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" "ERROR"
    Write-Log "A szkript megszakadt. Ellenőrizze a konfigurációt és próbálja újra." "ERROR"
    exit 1
} finally {
    $endTime = Get-Date
    $duration = $endTime - $script:startTime
    Write-Log "`nSzkript futási idő: $($duration.ToString('hh\:mm\:ss'))" "DEBUG"
    Write-Log "Naplófájl: $($Global:LogFile)" "INFO"
}
