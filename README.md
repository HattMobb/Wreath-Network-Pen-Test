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

## Enumeration of internal network

Using a static nmap binary, supplied by my attacking machine, I scanned the internal network for other hosts within scope.

![Screenshot 2023-06-06 104945](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/6471e710-0afd-40b7-addb-cfa971bec375)
![Screenshot 2023-06-06 105638](https://github.com/HattMobb/Wreath-Network-Pen-Test/assets/134090089/06f8e8cc-5eae-48e8-afec-3c7f157d3487)

Success, both .150 and .100 machines are fair game.


