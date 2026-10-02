// h3probe: make ONE HTTP/3 request with a library's Chrome profile, so the QUIC ClientHello and HTTP/3
// SETTINGS can be recorded by capture/lib/server.py's QUICServer (see ../run_h3.py).
// Usage: h3probe <case> <url>     cases: tls-client:Chrome_152 | tls-client:Chrome_152_PSK | tls-client:Chrome_150 | azuretls:Chrome
// Prints one JSON line: {"case","ok","proto","status","error"}. Certificate verification is off (local self-signed endpoint).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	azuretls "github.com/Noooste/azuretls-client"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type result struct {
	Case   string `json:"case"`
	OK     bool   `json:"ok"`
	Proto  string `json:"proto"`
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

func bogdan(name, url string) result {
	p, ok := map[string]profiles.ClientProfile{"Chrome_152": profiles.Chrome_152, "Chrome_152_PSK": profiles.Chrome_152_PSK, "Chrome_150": profiles.Chrome_150}[name]
	if !ok {
		return result{Error: "unknown profile"}
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), tls_client.WithClientProfile(p), tls_client.WithTimeoutSeconds(15),
		tls_client.WithInsecureSkipVerify(), tls_client.WithProtocolRacing())
	if err != nil {
		return result{Error: err.Error()}
	}
	req, _ := fhttp.NewRequest("GET", url, nil)
	req.Header.Set("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")
	r, err := c.Do(req)
	if err != nil {
		return result{Error: err.Error()}
	}
	defer r.Body.Close()
	io.ReadAll(r.Body)
	return result{OK: true, Proto: r.Proto, Status: r.StatusCode}
}

func azure(url string) result {
	s := azuretls.NewSession()
	defer s.Close()
	s.Browser = azuretls.Chrome
	s.InsecureSkipVerify = true
	if err := s.EnableHTTP3(); err != nil {
		return result{Error: "EnableHTTP3: " + err.Error()}
	}
	r, err := s.Do(&azuretls.Request{Method: "GET", Url: url, ForceHTTP3: true})
	if err != nil {
		return result{Error: err.Error()}
	}
	return result{OK: true, Proto: r.HttpResponse.Proto, Status: r.StatusCode}
}

func main() {
	cs, url := os.Args[1], os.Args[2]
	var res result
	switch {
	case strings.HasPrefix(cs, "tls-client:"):
		res = bogdan(strings.TrimPrefix(cs, "tls-client:"), url)
	case cs == "azuretls:Chrome":
		res = azure(url)
	default:
		res = result{Error: "unknown case"}
	}
	res.Case = cs
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
}
