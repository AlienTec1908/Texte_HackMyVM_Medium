# Texte - HackMyVM (Medium)
 
![Texte.png](Texte.png)

## Übersicht

*   **VM:** Texte
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Texte)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 24. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Texte_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Texte"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), der eine Upload-Funktion (`upload.php`) bereitstellte. Diese Funktion war anfällig für Command Injection im `filename`-Parameter des Uploads. Durch Manipulation dieses Parameters (z.B. `filename=";cat [datei]"`) und Auslesen der Base64-kodierten Ausgabe konnte der Inhalt der Datei `uiydasuiydasuicyxzuicyxziuctxzidsauidascxzAAA.txttxttxt` extrahiert werden. Diese enthielt die Credentials `kamila:hahaha$$$hahaha`. Mit diesen Credentials gelang der SSH-Login als Benutzer `kamila`. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung eines SUID/SGID-Binaries `/opt/texte`. Dieses Binary las unsicher die Konfigurationsdatei `~/.mailrc`. Durch Einfügen von `shell bash` in `kamila`s `.mailrc` und anschließendes Ausführen von `/opt/texte` wurde eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `gobuster`
*   `nmap`
*   `vi` / `nano`
*   `curl`
*   `Burp Suite` (oder manuelles POST für Command Injection)
*   `ssh`
*   `sudo` (versucht)
*   `ls`
*   `cat`
*   `find`
*   `file`
*   Standard Linux-Befehle (`cd`, `id`, `pwd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Texte" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.135`).
    *   Eintrag von `texte.hmv` in lokale `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Nginx 1.18.0 "TexteBoard").
    *   `gobuster` auf Port 80 fand `index.html` und eine sehr kleine `upload.php` (27 Bytes).
    *   Manuelle Analyse zeigte, dass `upload.php` eine Upload-Funktion mit Filter gegen `.PHP`-Dateien hatte.

2.  **Initial Access (RCE via Command Injection im Upload-Dateinamen):**
    *   Identifizierung einer Command Injection Schwachstelle im `filename`-Parameter von `upload.php` während des Datei-Uploads. Das Skript verwendete den unsanitisierten `filename` in einem `shell_exec("base64 [filename]")`-Aufruf.
    *   Auslesen des Quellcodes von `upload.php` mittels der Injection (`filename=";cat upload.php"`).
    *   Auslesen des Inhalts der Datei `uiydasuiydasuicyxzuicyxziuctxzidsauidascxzAAA.txttxttxt` (gefunden durch vorherige `ls`-Ausgabe via Injection) mittels `filename=";cat uiydasuiydasuicyxzuicyxziuctxzidsauidascxzAAA.txttxttxt"`.
    *   Die Datei enthielt die Credentials `kamila/hahaha$$$hahaha`.
    *   Erfolgreicher SSH-Login als `kamila` mit dem Passwort `hahaha$$$hahaha`.
    *   User-Flag `IdontneedPHP` in `/home/kamila/user.txt` gelesen.

3.  **Privilege Escalation (von `kamila` zu `root` via SUID-Binary und `.mailrc`):**
    *   `sudo -l` für `kamila` zeigte keine Sudo-Rechte.
    *   `find / -type f -perm -4000 ...` identifizierte ein SUID-Root und SGID-`kamila` Binary: `/opt/texte`.
    *   Erstellung/Bearbeitung der Datei `/home/kamila/.mailrc` und Hinzufügen der Zeile `shell bash`.
    *   Ausführung von `/opt/texte` als `kamila`. Das Binary las die manipulierte `.mailrc` und startete aufgrund der `shell bash`-Direktive eine Bash-Shell mit den Rechten des SUID-Binaries (Root).
    *   Erlangung einer Root-Shell.
    *   Root-Flag `IlovetextEs` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Command Injection im Dateinamen:** Der `filename`-Parameter eines Upload-Skripts wurde unsanitisiert in einem Shell-Befehl verwendet, was RCE ermöglichte.
*   **Klartext-Credentials in Datei:** Zugangsdaten wurden in einer verschleierten Textdatei im Web-Root gespeichert.
*   **SUID/SGID-Binary-Exploitation:** Ein SUID-Root-Binary (`/opt/texte`) las unsicher eine benutzerkontrollierte Konfigurationsdatei (`~/.mailrc`), was die Ausführung einer beliebigen Shell (hier `bash`) mit Root-Rechten ermöglichte.
*   **`.mailrc` Hijacking:** Manipulation der `.mailrc`-Datei zur Beeinflussung von Programmen, die diese Datei parsen.

## Flags

*   **User Flag (`/home/kamila/user.txt`):** `IdontneedPHP`
*   **Root Flag (`/root/root.txt`):** `IlovetextEs`

## Tags

`HackMyVM`, `Texte`, `Medium`, `Command Injection`, `File Upload Vulnerability`, `RCE`, `SUID Exploitation`, `.mailrc`, `Credentials in File`, `Linux`, `Web`, `Privilege Escalation`
