# Taurus - HackMyVM (Medium)
 
![Taurus.png](Taurus.png)

## Übersicht

*   **VM:** Taurus
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Taurus)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 8. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Taurus_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Taurus"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit SNMP-Enumeration, die den Benutzernamen `sarah` offenbarte. Eine mit `cupp` erstellte, auf `sarah` zugeschnittene Wortliste wurde mit `hydra` verwendet, um deren SSH-Passwort (`Sarah_2012`) zu knacken. Dies ermöglichte den initialen Zugriff. Als `sarah` wurde eine `sudo`-Regel gefunden, die erlaubte, ein Skript (`/opt/ftp`) als Benutzer `marion` auszuführen. Dieses Skript baute eine Klartext-FTP-Verbindung zu `localhost` auf. Durch Mitschneiden des Loopback-Traffics mit `tcpdump` während der Ausführung des Skripts wurden die FTP-Credentials für `marion` (`ilovesushis`) ausgespäht. Nach dem Wechsel zu `marion` zeigte `sudo -l`, dass `marion` `/usr/bin/ptar` (eine `tar`-Variante) als `root` ohne Passwort ausführen durfte. Dies wurde genutzt, um das `/root`-Verzeichnis zu archivieren, das Archiv zu extrahieren und so den privaten SSH-Schlüssel von `root` zu erlangen, was den direkten SSH-Login als `root` ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `snmp-check`
*   `cupp`
*   `hydra`
*   `ssh`
*   `sudo`
*   `bash`
*   `tcpdump`
*   `ptar`
*   `tar`
*   `ls`
*   `cat`
*   `cd`
*   `vi`
*   Standard Linux-Befehle (`id`, `pwd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Taurus" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration (SNMP, Username Profiling):**
    *   IP-Findung mit `arp-scan` (`192.168.2.125`).
    *   `nmap`-Scan identifizierte offenen Port 22 (SSH - OpenSSH 8.4p1) und gefilterten Port 21 (FTP).
    *   `snmp-check 192.168.2.125` (mit Community `public`) offenbarte Systeminformationen und den Benutzernamen/Kontakt `Sarah`.
    *   Erstellung einer benutzerdefinierten Passwortliste `sarah.txt` mit `cupp -i` (basierend auf dem Namen `sarah`).

2.  **Initial Access (SSH Brute Force als `sarah`):**
    *   `hydra -t64 -V ssh://192.168.2.125 -l sarah -P sarah.txt` knackte das SSH-Passwort für `sarah`: `Sarah_2012`.
    *   Erfolgreicher SSH-Login als `sarah` mit dem gefundenen Passwort.

3.  **Privilege Escalation (von `sarah` zu `marion` via FTP Credential Sniffing):**
    *   `sudo -l` als `sarah` zeigte: `(marion : marion) NOPASSWD: /usr/bin/bash /opt/ftp`.
    *   Starten von `tcpdump -A -s 10240 -i lo` zum Mitschneiden des Loopback-Traffics.
    *   Ausführen von `sudo -u marion /usr/bin/bash /opt/ftp`.
    *   Die `tcpdump`-Ausgabe zeigte die Klartext-FTP-Credentials: `USER marion` und `PASS ilovesushis`.
    *   Wechsel zum Benutzer `marion` (impliziert, z.B. via `su marion` mit dem Passwort `ilovesushis`).

4.  **Privilege Escalation (von `marion` zu `root` via `sudo ptar` Abuse):**
    *   `sudo -l` als `marion` zeigte: `(ALL) NOPASSWD: /usr/bin/ptar`.
    *   Ausführung von `sudo /usr/bin/ptar -cf /tmp/root.tar /root`, um das `/root`-Verzeichnis als Root zu archivieren.
    *   Ausführung von `tar -xf /tmp/root.tar -C /tmp/` als `marion`, um das Archiv zu entpacken.
    *   Im extrahierten Verzeichnis `/tmp/root/.ssh/` wurde der private SSH-Schlüssel `id_rsa` von `root` gefunden.
    *   Erfolgreicher SSH-Login als `root` mit dem extrahierten Schlüssel: `ssh -i /tmp/root/.ssh/id_rsa root@localhost`.
    *   User-Flag `17f97ddf297442c5ecf0230a8db97e9b` in `/home/marion/user.txt` gelesen (als Root).
    *   Root-Flag `f3c6d27bbd3e9cf452c6c4258d316ce0` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **SNMP Enumeration (Default Community String):** Der SNMP-Dienst mit dem Standard-Community-String `public` gab sensible Informationen preis, darunter einen Benutzernamen.
*   **Schwaches Passwort / Username Profiling:** Das Passwort für `sarah` konnte durch eine kleine, mit `cupp` generierte Wortliste geknackt werden.
*   **Unsichere `sudo`-Regel (Skript-Ausführung mit Credential Leak):** Ein Skript (`/opt/ftp`), das als anderer Benutzer (`marion`) ausgeführt werden konnte, verwendete Klartext-FTP-Credentials, die über Loopback-Sniffing (`tcpdump`) abgefangen werden konnten.
*   **Unsichere `sudo`-Regel (Archivierungstool):** Die Erlaubnis, `ptar` (eine `tar`-Variante) als `root` auszuführen, ermöglichte das Lesen beliebiger Dateien (hier des `/root`-Verzeichnisses und des Root-SSH-Schlüssels) durch Archivierung und anschließendes Entpacken als normaler Benutzer.
*   **Auslesen privater SSH-Schlüssel:** Ermöglichte passwortlosen Root-Login.

## Flags

*   **User Flag (`/home/marion/user.txt`):** `17f97ddf297442c5ecf0230a8db97e9b`
*   **Root Flag (`/root/root.txt`):** `f3c6d27bbd3e9cf452c6c4258d316ce0`

## Tags

`HackMyVM`, `Taurus`, `Medium`, `SNMP`, `cupp`, `Hydra`, `SSH`, `sudo Exploitation`, `tcpdump`, `FTP Credential Sniffing`, `ptar`, `tar`, `Privilege Escalation`, `Linux`
