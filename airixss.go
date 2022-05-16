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
        "context"
        "github.com/chromedp/cdproto/page"
        "github.com/chromedp/chromedp"
        "strings"
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

func main() {

        var concurrency int
        flag.IntVar(&concurrency, "c", 50,"")

        var xsspayload string
        flag.StringVar(&xsspayload, "payload", "alert(1)", "")
        flag.StringVar(&xsspayload, "p", "alert(1)", "")

        var proxy string
        flag.StringVar(&proxy,"proxy", "0","")
        flag.StringVar(&proxy,"x", "0","")

        var poc bool
        flag.BoolVar(&poc,"only-poc", false, "")
        flag.BoolVar(&poc,"s", false, "")

        var headless bool
        flag.BoolVar(&headless, "headless-mode", false, "")
        flag.BoolVar(&headless, "hm", false, "")

        var headers string
        flag.StringVar(&headers,"headers", "0", "")
        flag.StringVar(&headers,"H", "0", "")

        flag.Parse()

        std := bufio.NewScanner(os.Stdin)
        targets := make(chan string)

        var wg sync.WaitGroup
        for i:=0;i<concurrency;i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for v := range targets{

                            if headless != false{
                                h := HeadlessMode(v, poc, proxy)
                                if h != "not"{fmt.Println(h)}

                            }else{

                                x := getParams(v, xsspayload, proxy, headers, poc)
                                if x != "ERROR" {
                                        fmt.Println(x)
                                                }
                                    

                            }
                        }
                    

                }()
        }

        for std.Scan() {
            var line string = std.Text()
            targets <- line

        }
        close(targets)
        wg.Wait()

}

func getParams(urlt string, xssp string, proxy string, headers string, onlypoc bool) string {

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

        _, errx := url.Parse(urlt)
        if errx != nil {
            return "not"
         }

        client := &http.Client{
                Transport: trans,
                Timeout:   3 * time.Second,
        }

        if proxy != "0" {
            if p, err := url.Parse(proxy); err == nil {
                trans.Proxy = http.ProxyURL(p)
        }}

        res, err := http.NewRequest("GET", urlt, nil)
        res.Header.Set("Connection", "close")
        if headers != "0"{
            if strings.Contains(headers, ";"){
                    parts := strings.Split(headers, ";")
                    for _, q := range parts{
                        separatedHeader := strings.Split(q,":")
                        res.Header.Set(separatedHeader[0],separatedHeader[1])
                }
                }else{
                        sHeader := strings.Split(headers,":")
                        res.Header.Set(sHeader[0], sHeader[1])
}
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
        check_xss := strings.Contains(page, xssp)

        if onlypoc != false{
            if check_xss != false{
                return urlt
            }else{
                return "ERROR"
            }
        }

        if check_xss != false {
                return "\033[1;31mVulnerable To XSS - "+urlt+"\033[0;0m"
        }else{
                return "\033[1;30mNot Vulnerable to XSS - "+urlt+"\033[0;0m"
        }

}



func HeadlessMode(urlt string, poctype bool, proxyserver string) string {

    if proxyserver == "0"{

        _, errx := url.Parse(urlt)
        if errx != nil {
            return "not"
         }
        xssCheck := false


        ctx, cancel := chromedp.NewContext(
            context.Background(),
                )
        defer cancel()


        ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        chromedp.ListenTarget(ctx, func(ev interface{}) {
                if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
                        
                        xssCheck = true
                        cancel()
                }else{
                                go func() {
                                        chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
                                }()
                        }
                })



        err := chromedp.Run(ctx,
                chromedp.Navigate(urlt),
        )

        if err != nil {
            //
        }

        if poctype != false{
            if xssCheck != false{
                return urlt
            }else{
                return "not"
            }
        }

        if xssCheck != false{
                return "\033[1;31m[Critical] XSS Found - "+urlt+"\033[0;0m"
        }else{
                return "\033[1;30mNot Vulnerable to XSS - "+urlt+"\033[0;0m"
        }


    }else{

        _, errx := url.Parse(urlt)
        if errx != nil {
            return "not"
         }
        xssCheck := false

        o := append(chromedp.DefaultExecAllocatorOptions[:],
            chromedp.ProxyServer(proxyserver), 
            )
        
        cx, cancel := chromedp.NewExecAllocator(context.Background(), o...)
        defer cancel()

        ctx, cancel := chromedp.NewContext(cx)
        defer cancel()

       
        ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        chromedp.ListenTarget(ctx, func(ev interface{}) {
        if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {     
                xssCheck = true
                cancel()
        }else {
                go func() {
                    chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
                                }()
                        }
                })



        err := chromedp.Run(ctx,
                chromedp.Navigate(urlt),
        )
        
        if err != nil {
            //
        }


        if poctype != false{
            if xssCheck != false{
                return urlt
            }else{
                return "not"
            }
        }

        if xssCheck != false{
                return "\033[1;31m[Critical] XSS Found - "+urlt+"\033[0;0m"
        }else{
                return "\033[1;30mNot Vulnerable to XSS - "+urlt+"\033[0;0m"
        }



    }
}
