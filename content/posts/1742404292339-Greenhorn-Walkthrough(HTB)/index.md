---
title: "Greenhorn Walkthrough(Hack The Box)"
date: 2025-03-26
draft: true
description: "A straight forward walkthrough for Greenhorn box."
tags: ["Easy", "Linux", "Hack The Box", "Hacking", "Web", "Walkthrough"]
 
---
## About
GreenHorn is an easy difficulty machine that takes advantage of an exploit in Pluck to achieve Remote Code Execution and then demonstrates the dangers of pixelated credentials. The machine also showcases that we must be careful when sharing open-source configurations to ensure that we do not reveal files containing passwords or other information that should be kept confidential. 

## Reconnaissance  
- I scanned the ports with rustscan and we have three ports open 80,22,3000 respectively as shown in the below image
![Pasted image 20241225141303.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225141303.png?raw=true)
- First I checked Port 80 and it runs a website called greenhorn. The noticeable thing is it had a loginpage.  
- While poking areound more I found that this greenhorn page uses Pluck CMS, which is sensitive as it goes.

{{< badge >}} Definition {{< /badge >}}
- Pluck is a small and simple content management system (CMS), written in PHP. With Pluck, you can easily manage your own website. Pluck focuses on simplicity and ease of use. This makes Pluck an excellent choice for every small website. Licensed under the General Public License (GPL), Pluck is completely open source. This allows you to do with the software whatever you want, as long as the software stays open source.

- Onto the next port `3000`, It runs Gitea on it, Also it had repo of the greenhorn page from port `80`
![Pasted image 20241225163431.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225163431.png?raw=true)
- The crazy thing is I was able to access the repo without any form of authentication.
![crazy!](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExdGJ3Z3Jhc3Fzdmt6dXZ0OHozd3Uyc2FtdTk1c3RsdGUzNm0zbWg5dSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/BbJdwrOsM7nTa/giphy.gif)

## Enumeration
- As we got a exposed repo I was desperately searching for something sensitive, while on that `login.php` seemed Interesting. This `login.php` code performs some interesting functions like blocking users after five or some failed attempts.
{{< details summary="View the code" >}}

```
<?php
/*
 * This file is part of pluck, the easy content management system
 * Copyright (c) pluck team
 * http://www.pluck-cms.org

 * Pluck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * See docs/COPYING for the complete license.
*/

//First, define that we are in pluck.
define('IN_PLUCK', true);

//Then start session support.
session_start();

//Include security-enhancements.
require_once 'data/inc/security.php';
//Include functions.
require_once 'data/inc/functions.modules.php';
require_once 'data/inc/functions.all.php';
//Include variables.
require_once 'data/inc/variables.all.php';

//Check if we've installed pluck.
if (!file_exists('data/settings/install.dat')) {
	$titelkop = $lang['install']['not'];
	include_once 'data/inc/header2.php';
	redirect('install.php', 3);
	show_error($lang['install']['not_message'], 1);
	include_once 'data/inc/footer.php';
}

//If pluck is installed:
else {
	require_once 'data/settings/pass.php';

	//Check if we're already logged in. First, get the token.
	require_once 'data/settings/token.php';

	if (isset($_SESSION[$token]) && ($_SESSION[$token] == 'pluck_loggedin')) {
		header('Location: admin.php');
		exit;
	}

	//Include header-file.
	$titelkop = $lang['login']['title'];
	include_once 'data/inc/header2.php';

	//If password has been sent, and the bogus input is empty, MD5-encrypt password.
	if (isset($_POST['submit']) && empty($_POST['bogus'])) {
		$pass = hash('sha512', $cont1);

		//Create hash from user-IP, for brute-force protection.
		define('LOGIN_ATTEMPT_FILE', 'data/settings/loginattempt_'.hash('sha512', $_SERVER['REMOTE_ADDR']).'.php');

		//Check if user has tried to login before.
		if (file_exists(LOGIN_ATTEMPT_FILE)) {
			require(LOGIN_ATTEMPT_FILE);
			//Determine the amount of seconds that a user will be blocked (300 = 5 minutes).
			$timestamp = $timestamp + 300;

			//Block access if user has tried 5 times.
			if (($tries == 5)) {
				//Check if time hasn't exceeded yet, then block user.
				if ($timestamp > time())
					$login_error = show_error($lang['login']['too_many_attempts'], 1, true);
				//If time has exceeded, unblock user.
				else
					unlink(LOGIN_ATTEMPT_FILE);
			}
		}

		//If password is correct, save session-cookie.
		if (($pass == $ww) && (!isset($login_error))) {
			$_SESSION[$token] = 'pluck_loggedin';

			//Delete loginattempt file, if it exists.
			if (file_exists(LOGIN_ATTEMPT_FILE))
				unlink(LOGIN_ATTEMPT_FILE);

			//Display success message.
			show_error($lang['login']['correct'], 3);
			if (isset($_SESSION['pluck_before']))
				redirect($_SESSION['pluck_before'], 1);
			else
				redirect('admin.php?action=start', 1);
			include_once 'data/inc/footer.php';
			exit;
		}

		//If password is not correct; display error, and store attempt in loginattempt file for brute-force protection.
		elseif (($pass != $ww) && (!isset($login_error))) {
			$login_error = show_error($lang['login']['incorrect'], 1, true);

			//If a loginattempt file already exists, update tries variable.
			if (file_exists(LOGIN_ATTEMPT_FILE))
				$tries++;
			else
				$tries = 1;

			//Get current timestamp and save file.
			save_file (LOGIN_ATTEMPT_FILE, array('tries' => $tries, 'timestamp' => time()));
		}
	}
	?>
		<span class="kop2"><?php echo $lang['login']['password']; ?></span>
		<form action="" method="post">
			<input name="cont1" size="25" type="password" />
			<input type="text" name="bogus" class="displaynone" />
			<input type="submit" name="submit" value="<?php echo ucfirst($lang['login']['title']); ?>" />
		</form>
	<?php
	if (isset($login_error))
		echo $login_error;

	include_once 'data/inc/footer.php';
}
?>
```
{{< /details >}}

- Particularly this line of code `require_once 'data/settings/pass.php';` from `login.php` lead me to `data/settings/pass.php` path in the repo and it had a password hash.
``` 
<?php
$ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
?>
```
- As from the length we can say that this is a sha512 hash, So I cracked it using hashcat 
![Pasted image 20241225163840.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225163840.png?raw=true)
- Using the cracked password I logged in on the greenhorn website as admin, which is cool!
![cool](https://media1.tenor.com/m/HR98MsC-pIgAAAAC/cool-i-guess-star-fox.gif)
- While enumerating I found an exploit on exploit-DB for pluck (ref: [CVE-2023-50564](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC))
- Many CMS can be exploited by shipping a bad piece code to it's managed web. Similar to the Sea box this CMS can also be exploited by installing a module with malicious code within it.
- I made a zip with reverseshell.php(Malicious code for reverse shell) included in it.
![Pasted image 20241225164451.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225164758.png?raw=true)

## Exploitation
- To install the module I went to `manage modules` and uploaded the zip by clicking `install module`
- Then I found out installed modules are stored like this `<URL>/data/modules/<zip_extracts_here>` with the help of repo
- Triggered the reverse shell by visiting the malicious code(i.e. reverseshell.php) and got the connection
![Pasted image 20241225164758.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225164758.png?raw=true)

## Pivoting
- From enumeration I learnt that there is an user called `junior` on the machine.
![Pasted image 20241225164853.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225164853.png?raw=true)
- I just tried using the previously cracked password and it worked for the user `junior`
- Got  the {{< keyword >}} User flag {{< /keyword >}}
![Pasted image 20241225165007.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225165007.png?raw=true)

## Privilege Escalation
- In the home directory of junior, there is not only user flag but also a file named `Using OpenVAS.pdf` was also there.
- So I transferred the pdf file to my attack machine
![Pasted image 20241225165235.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225165235.png?raw=true)
- These were it's contents
![Pasted image 20241225165315.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225165315.png?raw=true)
- Interesting right, Root password is blured
![interesting](https://media.giphy.com/media/3oKIPl97G9KsnxS3XG/giphy.gif?cid=790b7611djcza1sxhh3u5h2y36vq1fhv6p0fl3l0pyhdtizl&ep=v1_gifs_search&rid=giphy.gif&ct=g)
- From this [article](https://labs.jumpsec.com/can-depix-deobfuscate-your-data/) I found that actually, blured part can be recovered 
- Using this tool [Depixelization](https://github.com/spipm/Depixelization_poc) I can easily recontruct the particular blured sentence
- There is an option in my pdf reader to extract only the pix-elated part from the PDF as an image which was convinient for me.
![Pasted image 20241225165809.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225165809.png?raw=true)
- I Saved the image as `png` and then used the tool on that to get the original text
```bash
python3 depix.py -p ../pixel.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o ../download-notepad_Windows10_closeAndSpaced.png
```
![Pasted image 20241225165946.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225165946.png?raw=true)
- Got the root user's password
![Pasted image 20241225170036.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225170036.png?raw=true)
- Logged in as root and got the {{< keyword >}} Root flag {{< /keyword >}}
![Pasted image 20241225170134.png](https://github.com/Emp5r0R/Db_of-pics/blob/main/Pasted%20image%2020241225170134.png?raw=true)

{{< typeit >}} I know you are worried that this walkthrough is ending. I know that you are craving for my wrtting, Don't worry mate there are plenty of posts in this website made especially for you. Feel free to read them. Anyway it's time for me to go, see you next time {{< /typeit >}}

![bye](https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZTRiNXVtdTgwdXF5ejU2b2hwZmV2amhnbDhiaWhvM2JmanBpNWg4YyZlcD12MV9naWZzX3NlYXJjaCZjdD1n/Ij8Mc51BNYHRXfcilv/giphy.gif)
