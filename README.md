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







