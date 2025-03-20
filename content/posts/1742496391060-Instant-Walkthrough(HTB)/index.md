---
title: "Instant Walkthrough(HTB)"
date: 2025-03-20
draft: true
description: "a description"
tags: ["Medium", "Linux", "HTB", "hacking", "Web", "Android", "Walkthrough"]
---
## Reconnaissance #Linux 
- We got exactly two ports open web and ssh
- ![[Pasted image 20241222223503.png]]
- When accessing the web it gives an option to download a mobile app. That also in two places
- ![[Pasted image 20241222223731.png]]
- Even this button downloads the app called `instant.apk`
- ![[Pasted image 20241222223929.png]]
## Enumeration
- I have downloaded and used this tool [jadx](https://github.com/skylot/jadx?tab=readme-ov-file) to decompile the java code from the android app
- While running and it gave me the decompiled code
- ![[Pasted image 20241222224706.png]]
- While recursive grepping the files `grep -r "instant"` I got admin jwt token
- ![[Pasted image 20241222222123.png]]
- And also found some api endpoints
- I got swagger api endpoint too 
- ![[Pasted image 20241222224908.png]]
- when I access it can see all beautiful endpoints .
- One in particular looks interesting , which is a an endpoint to red logs. With that I have read `/etc/passwd` and found the users info
- ![[Pasted image 20241222231821.png]]
## Exploitation
- With this I requested for `shirohige/.ssh/id_rsa` file for login
- I logged in with file after some cleaning
```
ssh -i id_rsa -vl shirohige instant.htb 
```
- ![[Pasted image 20241222233027.png]]
- Got the user flag
- ![[Pasted image 20241222233106.png]]
## Privilege Escalation
- I came across an SQLite database file named **instant.db** located in the directory **/projects/mywallet/Instant-Api/mywallet/instance**. Upon closer inspection, this database contained usernames and their corresponding hashed passwords.
- The password hashes were generated using **Werkzeug hashing**
- Started cracking the hashes.
- After that I discovered some backups of Putty sessions from `/opt` directory 
- By supplying the correct password with the session code in file we can get it decoded using this tool [SolarPuttyDecrypt](https://github.com/VoidSec/SolarPuttyDecrypt)
- ![[Pasted image 20241223021105.png]]
- We got the password for root
- Got the root flag
- ![[Pasted image 20241223021213.png]]
