<h1 align="center">Airixss</h1> <br>

<p align="center">
  <a href="#--usage--explanation">Usage</a> •
  <a href="#--installation--requirements">Installation</a>
</p>

<h3 align="center">Airixss is for checking reflection in recon process to find xss vulnerable.</h3>

<img src="https://cdn.discordapp.com/attachments/897664569323974706/954517164021403718/unknown.png">

## - Installation & Requirements:
```
> git clone https://github.com/ferreiraklet/airixss.git

> cd airi

> go build main.go

> mv main airixss

> chmod +x airixss

> ./airixss -h
```
<br>


## - Usage & Explanation:
  In Your recon process, you may find endpoints that can be vulnerable to xss,
  
  Ex: https://redacted.com/index.php?msg=SameValue
  
  By replacing the "SameValue" to a xss payload, In order to see if there is reflection/vulnerable, it is when you use airixss
  
  
  
  Lets say you have a url and you want to test reflection:
  
  
  
  Airixss reads from stdin:
  ```echo 'https://redacted.com/index.php?user="><img src=x onerror=confirm(1)>' | airixss -payload 'confirm(1)'```
  
  
  
  In -payload flag, you need to specify a part of the payload used in url, -payload "value_will_be_checked_reflection"
  
  You can use a file containing a list of targets as well:
  
  cat targets | airixss -payload "alert(1)"
  
  
  **You can make use of Airixss with other tools such gau, gauplus, waybackurls, qsreplace and bhedak**
  Another examples of usage:
  
  ```echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><img src=x onerror=prompt(1)>' | airixss -payload '<img src=x onerror=prompt(1)>'```
  
  ```echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"```

<br>



## This project is for educational and bug bounty porposes only! I do not support any illegal activities!.

If any error in the program, talk to me immediatly.
