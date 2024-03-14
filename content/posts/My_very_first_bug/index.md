---
title: "My very first bug"
date: 2023-04-21
draft: false
summary: "My first bug I found in Real World stuff. A LAN bug in RAXE300 Netgear device"
tags: ["Netgear"]
---


--------------------------

### background

After studied about security and played CTF for a year, I decide to move on to the real world playground, and I choose Nighthawk RAXE300 as a target. Below is how I found the command injection bug in Nighthawk RAXE300. 


After studying of hacking router devices, I realized that common LAN bug come from many of services such as: `hostapd`,  `httpd`, `smb`,... So when started to analyze the RAXE300 firmware, I'm try to reverse some files like: `pudil`, `pucfu`, `dhcpc`, `puhttpsniff`, they took me a lot of time and efford for reversing. When I stop at `puhttpsniff`, It's quite an interested file and code base of it quite small, so I decide to dig deep into `puhttpsniff`. 

### LAN bug in RAXE300 firmware 

I discovered one of the many vulnerabilities of RAXE300 was the command injection in --user-agent field of the device. The bug lie in the function at address 0x10EC0 of `puhttpsniff` binary file, you can see in the below snippet: 

```c
char *__fastcall sub_10EC0(const char *a1, int a2, _WORD *a3, int a4)
{
    ...
    result = strstr(a1, "User-Agent: ");
    if ( result )
    {
        _isoc99_sscanf(result + 12, "%255[^\r\n]", v17);
        ....
    
            
        sprintf((char *)v18, "pudil -i %s \"%s\"", v12, (const char *)v17);
        result = (char *)system((const char *)v18);
    ...
    }
    ...
}

```
In summary, the above function, it takes contents from `User-Agent` field and pass it into the second argument of `pudil` command and run it with `system` command.

As you can see the above code. First it find does `User-Agent` exist in `a1` variable by `result = strstr(a1, "User-Agent: ");` , after that it reads input with `_isoc99_sscanf(result + 12, "%255[^\r\n]", v17);` and store it in `v17` variable. Next it pass `v17` as the second argument into `pudil` command and store the string in `v18` variable, `sprintf((char *)v18, "pudil -i %s \"%s\"", v12, (const char *)v17);`. After that it run the command by `system` function with `v18` is the first argument. 

Because it doesn't check some special character, so we can easy to exploit the command injection bug with ` character. 

```PoC: curl --user-agent "a`ls`" 192.168.0.1```
