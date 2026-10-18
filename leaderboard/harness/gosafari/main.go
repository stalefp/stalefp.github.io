// Safari-profile cases of the leaderboard harness (same shape as gofirefox; the Chrome and Firefox harnesses are untouched).
// Each case makes one real request to the TLS echo endpoint and writes out/<case>.json.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	azuretls "github.com/Noooste/azuretls-client"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const URL = "https://tls.peet.ws/api/all"

// Safari's usual navigation header set and order (desktop Safari on macOS); the behaviour probe uses the captured order.
var ffHdr = [][2]string{
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{"sec-fetch-site", "none"}, {"accept-encoding", "gzip, deflate, br"}, {"sec-fetch-mode", "navigate"},
	{"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"},
	{"accept-language", "en-US,en;q=0.9"}, {"sec-fetch-dest", "document"}, {"priority", "u=0, i"},
}

func bogdan(p profiles.ClientProfile) ([]byte, error) {
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), tls_client.WithClientProfile(p), tls_client.WithTimeoutSeconds(30))
	if err != nil {
		return nil, err
	}
	req, _ := fhttp.NewRequest("GET", URL, nil)
	order := []string{}
	for _, h := range ffHdr {
		req.Header.Set(h[0], h[1])
		order = append(order, h[0])
	}
	req.Header[fhttp.HeaderOrderKey] = order
	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func azure() ([]byte, error) {
	s := azuretls.NewSession()
	defer s.Close()
	s.Browser = azuretls.Safari
	oh := azuretls.OrderedHeaders{}
	for _, h := range ffHdr {
		oh = append(oh, []string{h[0], h[1]})
	}
	r, err := s.Get(URL, oh)
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

func utlsAuto() ([]byte, error) {
	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, n, a)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(a)
		u := utls.UClient(raw, &utls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}, utls.HelloSafari_Auto)
		if err := u.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return u, nil
	}}
	req, _ := http.NewRequest("GET", URL, nil)
	for _, h := range ffHdr {
		req.Header.Set(h[0], h[1])
	}
	r, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func main() {
	os.MkdirAll("out", 0755)
	cases := map[string]func() ([]byte, error){
		"tls-client(go)_Safari_16_0":   func() ([]byte, error) { return bogdan(profiles.Safari_16_0) },
		"tls-client(go)_Safari_15_6_1": func() ([]byte, error) { return bogdan(profiles.Safari_15_6_1) },
		"azuretls_Safari":              azure,
		"utls_HelloSafari_Auto":        utlsAuto,
	}
	for name, f := range cases {
		if !wanted(name) {
			continue
		}
		b, err := f()
		if err != nil {
			fmt.Println(name, "ERR", err)
			continue
		}
		var js map[string]any
		if json.Unmarshal(b, &js) != nil {
			fmt.Println(name, "bad json", string(b[:min(200, len(b))]))
			continue
		}
		os.WriteFile("out/"+name+".json", b, 0644)
		fmt.Println(name, "ok")
	}
}

// wanted: STALE_LIBS (comma-separated board library names, e.g. "tls-client,uTLS") limits the run to those libraries;
// empty = every case. Used by the release watch to re-test only the library that shipped an update.
func wanted(name string) bool {
	v := os.Getenv("STALE_LIBS")
	if v == "" {
		return true
	}
	lib := map[string]string{"tls-client(go)": "tls-client", "azuretls": "azuretls-client", "utls": "uTLS"}[strings.SplitN(name, "_", 2)[0]]
	for _, x := range strings.Split(v, ",") {
		if strings.TrimSpace(x) == lib {
			return true
		}
	}
	return false
}
