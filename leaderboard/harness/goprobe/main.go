// Go side of the behaviour probe (../probe.py). One client per case, N requests on that SAME client; the probe server
// closes each connection after one response, so every request is a new TLS connection (resumption + extension order).
// Headers come in the browser's captured order through each library's ordered-header option.
//
//	goprobe <library> <profile> <browser> <url> <n> <headers-json>
//
// To add a Go library: write a factory (profile, browser, headers) -> func(url) error, add it to adapters, and add the
// library name to GO_LIBS in ../probe.py.
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
	"strconv"
	"strings"

	azuretls "github.com/Noooste/azuretls-client"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type getter func(url string) error

func tlsClient(profile, browser string, hdrs [][2]string) (getter, error) {
	p, ok := profiles.MappedTLSClients[strings.ToLower(profile)]
	if !ok { // keys look like "chrome_152_PSK": lowercase name, uppercase suffix
		p, ok = profiles.MappedTLSClients[strings.Replace(strings.ToLower(profile), "_psk", "_PSK", 1)]
	}
	if !ok {
		return nil, fmt.Errorf("unknown tls-client profile %s", profile)
	}
	opts := []tls_client.HttpClientOption{tls_client.WithClientProfile(p), tls_client.WithTimeoutSeconds(20), tls_client.WithInsecureSkipVerify()}
	if browser == "chrome" { // same setting as gobench (Chrome cases use random extension order)
		opts = append(opts, tls_client.WithRandomTLSExtensionOrder())
	}
	c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	return func(url string) error {
		req, _ := fhttp.NewRequest("GET", url, nil)
		order := []string{}
		for _, h := range hdrs {
			req.Header.Set(h[0], h[1])
			order = append(order, h[0])
		}
		req.Header[fhttp.HeaderOrderKey] = order
		r, err := c.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return nil
	}, nil
}

func azure(profile, browser string, hdrs [][2]string) (getter, error) {
	s := azuretls.NewSession()
	s.Browser = map[string]string{"Chrome": azuretls.Chrome, "Firefox": azuretls.Firefox, "Safari": azuretls.Safari}[profile]
	if s.Browser == "" {
		return nil, fmt.Errorf("unknown azuretls browser %s", profile)
	}
	s.InsecureSkipVerify = true
	oh := azuretls.OrderedHeaders{}
	for _, h := range hdrs {
		oh = append(oh, []string{h[0], h[1]})
	}
	return func(url string) error { _, err := s.Get(url, oh); return err }, nil
}

func uTLS(profile, browser string, hdrs [][2]string) (getter, error) {
	id, ok := map[string]utls.ClientHelloID{"HelloChrome_Auto": utls.HelloChrome_Auto, "HelloFirefox_Auto": utls.HelloFirefox_Auto,
		"HelloSafari_Auto": utls.HelloSafari_Auto, "HelloIOS_Auto": utls.HelloIOS_Auto}[profile]
	if !ok {
		return nil, fmt.Errorf("unknown uTLS hello %s", profile)
	}
	cache := utls.NewLRUClientSessionCache(32)
	tr := &http2.Transport{DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, n, a)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(a)
		u := utls.UClient(raw, &utls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true, ClientSessionCache: cache}, id)
		if err := u.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return u, nil
	}}
	cl := &http.Client{Transport: tr}
	return func(url string) error {
		req, _ := http.NewRequest("GET", url, nil)
		for _, h := range hdrs {
			req.Header.Set(h[0], h[1])
		}
		r, err := cl.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return nil
	}, nil
}

var adapters = map[string]func(string, string, [][2]string) (getter, error){"tls-client": tlsClient, "azuretls-client": azure, "uTLS": uTLS}

func main() {
	lib, profile, browser, url := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	n, _ := strconv.Atoi(os.Args[5])
	var hdrs [][2]string
	json.Unmarshal([]byte(os.Args[6]), &hdrs)
	out := map[string]any{"ok": false, "done": 0}
	defer func() { b, _ := json.Marshal(out); fmt.Println(string(b)) }()
	f, ok := adapters[lib]
	if !ok {
		out["error"] = "no Go adapter for " + lib
		return
	}
	get, err := f(profile, browser, hdrs)
	if err != nil {
		out["error"] = err.Error()
		return
	}
	for i := 0; i < n; i++ {
		if err := get(fmt.Sprintf("%s&i=%d", url, i)); err != nil {
			out["error"] = err.Error()
			break
		}
		out["done"] = i + 1
	}
	out["ok"] = out["done"].(int) > 0
}
