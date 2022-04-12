[![made-with-Go](https://img.shields.io/badge/made%20with-Go-brightgreen.svg)](http://golang.org)
<h1 align="center">Airixss</h1> <br>

<p align="center">
  <a href="#--usage--explanation">Usage</a> •
  <a href="#--installation--requirements">Installation</a>
</p>

<h3 align="center">Airixss is for checking reflection in recon process to find possible xss vulnerable endpoints.</h3>

<img src="https://cdn.discordapp.com/attachments/876919540682989609/962814461650018354/unknown.png">


## Contents:

- [Installation](#--installation--requirements)
- [Usage](#--usage--explanation)
  - [Adding Headers](#adding-headers)
  - [Using Proxy](#using-proxy)
  - [Headless Mode](#headless-mode)
  - [Using with other tools](#chaining-with-other-tools)

## - Installation & Requirements:
You need to install chromedp lib first ->
```bash
▶ go get -u github.com/chromedp/chromedp
```

Installing the tool ->

Using go
```bash
▶ go get -u github.com/ferreiraklet/airixss
```
Using git clone
```bash
▶ git clone https://github.com/ferreiraklet/airixss.git
▶ cd airixss
▶ go build airixss.go
▶ chmod +x airixss
▶ ./airixss -h
```
<br>


## - Usage & Explanation:

In Your recon process, you may find endpoints that can be vulnerable to xss,
  
* Ex: https://redacted.com/index.php?msg=SameValue
  
* By replacing the "SameValue" to a xss payload, In order to see if there is reflection/vulnerable, it is when you use airixss
  

<br>
  
### Stdin - Single urls

```bash
echo 'https://redacted.com/index.php?user=%22%3E%3Csvg%20onload%3Dconfirm%281%29%3E' | airixss -payload "confirm(1)"

echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"
```
In -payload flag, you need to specify a part of the payload used in url, -payload "value_will_be_checked_reflection"
  
### Stdin - Read from File

```bash
cat targets | airixss -payload "alert(1)"
```

### Adding Headers

Pay attention to the syntax!
```bash
echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" -H "header1: value1;Header2: value2"
```

### Using Proxy
 
```bash
echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" --proxy "http://yourproxy"
```
### Headless Mode

**Headless mode is a "simulated" browser process that checks for the xss pop-up**

It has much more accuracy, however, it is slower than normal method.
( experimental mode )

**Usage**:
 * **Attention** - Using more than 5 concurrencys may generate errors!
```bash
echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><svg onload=confirm(1)>' | airixss --headless-mode -c 5

echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><svg onload=confirm(1)>' | airixss --headless-mode --only-poc -c 5
```
Using Proxy:
```bash
echo "http://testphp.vulnweb.com:80/hpp/index.php?pp=x" | qsreplace '"><svg onload=confirm(1)>' | airixss --headless-mode -c 5 --proxy "http://yourproxy"
```

### Chaining with other tools
```bash
echo "http://testphp.vulnweb.com" | waybackurls | anew | gf xss | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1) -H "Header1: Value1;Header2: value2"

echo "http://testphp.vulnweb.com" | waybackurls | nilo | anew | gf xss | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1) -H "Header1: Value1;Header2: value2" --proxy "http://yourproxy"

echo "http://testphp.vulnweb.com" | waybackurls | nilo | anew | gf xss | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1) -H "Header1: Value1;Header2: value2" --proxy "http://yourproxy"

echo "http://testphp.vulnweb.com" | waybackurls | anew | gf xss | nilo | qsreplace '"><svg onload=confirm(1)>' | airixss --headless-mode --only-poc -c 5
```
    

## Check out some of my other programs <br>

> [Nilo](https://github.com/ferreiraklet/nilo) - Checks if URL has status 200

> [Jeeves](https://github.com/ferreiraklet/jeeves) - Time based blind Injection Scanner

## Please, also check these => <br>
> [GXSS](https://github.com/KathanP19/Gxss)

> [Dalfox](https://github.com/hahwul/dalfox)


If any error in the program, talk to me immediatly.
## This project is for educational and bug bounty porposes only! I do not support any illegal activities!.
