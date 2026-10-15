// Firefox-profile cases of the leaderboard harness (separate from gobench so the Chrome harness is untouched).
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

	azuretls "github.com/Noooste/azuretls-client"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const URL = "https://tls.peet.ws/api/all"

// Header names and order as captured from real Firefox (capture/data/firefox/latest.json); values are Firefox's usual navigation values.
var ffHdr = [][2]string{
	{"user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0"},
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{"accept-language", "en-US,en;q=0.5"}, {"accept-encoding", "gzip, deflate, br, zstd"},
	{"upgrade-insecure-requests", "1"}, {"sec-fetch-dest", "document"}, {"sec-fetch-mode", "navigate"},
	{"sec-fetch-site", "none"}, {"sec-fetch-user", "?1"}, {"priority", "u=0, i"}, {"te", "trailers"},
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
	req.Header[fhttp.PHeaderOrderKey] = []string{":method", ":path", ":authority", ":scheme"}
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
	s.Browser = azuretls.Firefox
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
		u := utls.UClient(raw, &utls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}, utls.HelloFirefox_Auto)
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
		"tls-client(go)_Firefox_148": func() ([]byte, error) { return bogdan(profiles.Firefox_148) },
		"tls-client(go)_Firefox_147": func() ([]byte, error) { return bogdan(profiles.Firefox_147) },
		"azuretls_Firefox":           azure,
		"utls_HelloFirefox_Auto":     utlsAuto,
	}
	for name, f := range cases {
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
