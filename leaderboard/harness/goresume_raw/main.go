// Copy of ../../../goresume/main.go that also saves the raw echo JSON for every request,
// so the leaderboard can diff the full ClientHello (not just the JA4) for fresh and resumed connections.
// Usage: goresume_raw <outdir> [url]
package main

import (
	"strings"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

func main() {
	out := "out"
	url := "https://tls.peet.ws/api/all"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if len(os.Args) > 2 {
		url = os.Args[2]
	}
	os.MkdirAll(out, 0755)
	if !wanted("tls-client(go)_resume") {
		return
	}
	for name, p := range map[string]profiles.ClientProfile{"Chrome_152": profiles.Chrome_152, "Chrome_152_PSK": profiles.Chrome_152_PSK} {
		c, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), tls_client.WithClientProfile(p), tls_client.WithTimeoutSeconds(30))
		for i := 0; i < 3; i++ {
			req, _ := fhttp.NewRequest("GET", url, nil)
			r, err := c.Do(req)
			if err != nil {
				fmt.Println(name, err)
				break
			}
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			var d struct {
				TLS struct {
					JA4 string `json:"ja4"`
				} `json:"tls"`
			}
			if json.Unmarshal(b, &d) == nil {
				os.WriteFile(filepath.Join(out, fmt.Sprintf("tls-client(go)_%s_req%d.json", name, i+1)), b, 0644)
			}
			fmt.Println(name, "req", i+1, d.TLS.JA4)
			c.CloseIdleConnections()
			time.Sleep(500 * time.Millisecond)
		}
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
