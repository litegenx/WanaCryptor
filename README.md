## References:

+ https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
+ https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010
+ https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
+ https://www.symantec.com/security_response/vulnerability.jsp?bid=96707
+ https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/[MS-SMB2]-151016.pdf
+ https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx
+ https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
+ https://community.rapid7.com/community/metasploit/blog/2017/04/03/introducing-rubysmb-the-protocol-library-nobody-else-wanted-to-write
+ https://msdn.microsoft.com/en-us/library/ee441741.aspx
+ https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_smb.py
+ http://stackoverflow.com/questions/38735421/packing-an-integer-number-to-3-bytes-in-python
+ https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html

```powershell
$ python2.7 wanacryptor.py IP
[+] [192.168.206.152] is likely VULNERABLE to MS17-010! (Windows 7 Ultimate 7600)

$ python2.7 wanacryptor.py IP
[+] [IP] is likely VULNERABLE to MS17-010! (Windows 5.1)
```
