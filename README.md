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
