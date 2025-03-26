---
title: "Instant Walkthrough(Hack The Box)"
date: 2025-03-26
draft: true
description: "A short and awesome walkthrough"
tags: ["Medium", "Linux", "Hack The Box", "hacking", "Web", "Android", "Walkthrough"] 
---
## Reconnaissance
- During the initial scan, we identified two open ports:
> Port 80 (HTTP) - Web Server

> Port 22 (SSH) - Secure Shell

![Pasted image 20241222223503.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222223503.png?raw=true)

- Upon accessing the web application, we noticed an option to download a mobile app, which was available in two places on the site.

![Pasted image 20241222223731.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222223731.png?raw=true)

- Clicking on the button initiated a download for an application named instant.apk.

![Pasted image 20241222223929.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222223929.png?raw=true)

## Enumeration
- To analyze the Android application, I downloaded and used jadx to decompile the Java code.
![Pasted image 20241222224706.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222224706.png?raw=true)
- While recursive grepping the files `grep -r "instant"` I got admin jwt token
![Pasted image 20241222222123.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222222123.png?raw=true)
- Additionally, I found multiple API endpoints, including a Swagger API documentation page.
![Pasted image 20241222224908.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222224908.png?raw=true)
- when I access it I can see all beautiful endpoints.
![beautiful](https://media1.tenor.com/m/fPpPW3fVISkAAAAd/it%27s-so-beautiful-grady-smith.gif)
- Upon accessing the Swagger UI, I could see all the available API endpoints. One particularly interesting endpoint allowed reading system logs. Exploiting this, I was able to read `/etc/passwd` and retrieve system user information.
![Pasted image 20241222231821.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222231821.png?raw=true)

## Exploitation
- By leveraging the API vulnerability, I requested access to shirohige's private SSH key stored at:
```
/home/shirohige/.ssh/id_rsa
```
- After cleaning the key, I used it to log in via SSH:
```
ssh -i id_rsa -vl shirohige instant.htb 
```
![Pasted image 20241222233027.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222233027.png?raw=true)
- Got the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241222233106.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241222233106.png?raw=true)

## Privilege Escalation
- While exploring the system, I discovered an SQLite database file named instant.db in:

``` 
/projects/mywallet/Instant-Api/mywallet/instance
```
- Upon inspecting the database, I found a table containing usernames and hashed passwords.
- The hashes were generated using Werkzeug hashing.

- I started cracking the hashes to retrieve plaintext passwords.

- Additionally, I found backup files of Putty sessions stored in the /opt directory. These session files contained encoded credentials.
By using the [SolarPuttyDecrypt](https://github.com/VoidSec/SolarPuttyDecrypt) tool, I was able to decrypt the stored credentials. 

![Pasted image 20241223021105.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241223021105.png?raw=true)

- With the retrieved password, I gained root access.
- Got the {{< keyword >}} Root flag {{< /keyword >}}

![Pasted image 20241223021213.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241223021213.png?raw=true)

{{< typeit >}} This walkthrough showcases multiple attack vectors including Android app analysis, API exploitation, and credential decryption, making it an exciting challenge for Hack The Box players. See you again on a longer post next time {{< /typeit >}}

![end](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExamg2bTE1cGJ0ODU3NWd5MDI4c2R0a3RpMHk1dGh4dTZ0NTY2dnY4byZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/JshL4uZk1tZt5W0TWV/giphy.gif)
