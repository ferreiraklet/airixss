package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func init() {
	flag.Usage = func() {
		help := []string{
			"Airi XSS confirmer",
			"",
			"Usage:",
			"+=======================================================+",
			"       -payload,     Reflection Flag, see readme for more information",
			"       -h            Show This Help Message",
			"",
			"+=======================================================+",
			"",
		}
		
		fmt.Fprintf(os.Stderr, strings.Join(help, "\n"))
		fmt.Println(`		
      __   _
    _(  )_( )_
   (_   _    _)
  / /(_) (__)
 / / / / / /
/ / / / / /

It's Raining XSS!`)
	
	}

}

func main() {

	var xsspayload string
	flag.StringVar(&xsspayload, "payload","","")
	// var target string
	// flag.StringVar(&target, "u", "","")
	// flag.StringVar(&target, "url", "", "")
	flag.Parse()

	if xsspayload == "" {
		fmt.Println("You need to specify a part of the payload used\nEx: -payload alert(1)\nExiting...")
		os.Exit(1)
	}
	var urls []string
	std := bufio.NewScanner(os.Stdin)
	for std.Scan() {
		var line string = std.Text()
		hline := strings.Replace(line, "%2F", "/", -1)
		line = hline
		// fmt.Println(line)

		urls = append(urls, line)

	}
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(url string) {

			defer wg.Done()

			x := getParams(url, xsspayload)
			if x != "ERROR" {
				fmt.Println(x)
			}
			//fmt.Println(pms, url)

		}(u)
	}

	wg.Wait()

}

func getParams(url string, xssp string) string {

	var trans = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: trans,
		Timeout:   3 * time.Second,
	}

	res, err := http.NewRequest("GET", url, nil)
	res.Header.Set("Connection", "close")
	resp, err := client.Do(res)
	// res.Header.Set("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36")

	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "ERROR"
	}

	page := string(body)
	check_xss := strings.Contains(page, xssp)
	if check_xss != false {
		return "\033[1;31mVulnerable To XSS - "+url+"\033[0;0m"
	}else{
		return "\033[1;30mNot Vulnerable to XSS - "+url+"\033[0;0m"
	}

}

