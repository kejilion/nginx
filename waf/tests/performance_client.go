// Offline load generator and deterministic origin for performance.py.
// Uses only the Go standard library; never connects to a public address.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type totals struct {
	sync.Mutex
	Count, Errors, Bytes, Skipped int64
	Codes                         map[int]int64
	Protocols                     map[string]int64
	Histogram                     [100001]int64 // 100 us buckets, capped at the request timeout.
	ServiceHistogram              [100001]int64
}

func bucket(d time.Duration) int {
	n := int(d / (100 * time.Microsecond))
	if n > 100000 {
		return 100000
	}
	return n
}
func percentile(h *[100001]int64, count int64, p float64) float64 {
	if count == 0 {
		return 0
	}
	target := int64(float64(count)*p + 0.999999)
	var seen int64
	for i, n := range h {
		seen += n
		if seen >= target {
			return float64(i+1) / 10
		}
	}
	return 10000
}

func backend(sock string) {
	l, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	if err := os.Chmod(sock, 0666); err != nil {
		panic(err)
	}
	s := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 32768,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 16<<20))
			if err != nil {
				http.Error(w, "body", 413)
				return
			}
			if r.URL.Path == "/sse" {
				w.Header().Set("Content-Type", "text/event-stream")
				f := w.(http.Flusher)
				for i := 0; i < 20; i++ {
					if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
						return
					}
					f.Flush()
					time.Sleep(50 * time.Millisecond)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, "{\"bytes\":%d}", n)
		})}
	if err := s.Serve(l); err != nil {
		panic(err)
	}
}

func main() {
	mode := flag.String("mode", "load", "backend or load")
	sock := flag.String("socket", "/test/front.sock", "Unix socket")
	target := flag.String("target", "unix", "unix or tls")
	workload := flag.String("workload", "static", "static/json/json64/upload/attack/attack-json/sse")
	duration := flag.Duration("duration", 10*time.Second, "measurement duration")
	concurrency := flag.Int("concurrency", 32, "bounded in-flight requests")
	rate := flag.Int("rate", 0, "scheduled requests per second; 0 = closed loop")
	hosts := flag.Int("hosts", 20, "virtual hosts")
	identity := flag.String("identity", "proxy", "proxy or direct")
	expectedStatus := flag.Int("expected-status", 200, "business response or deliberate WAF denial")
	flag.Parse()
	if *mode == "backend" {
		backend(*sock)
		return
	}
	if *mode != "load" || *concurrency < 1 || *concurrency > 512 || *rate < 0 || *rate > 10000 || *hosts < 1 || *hosts > 200 || *duration < time.Second || *duration > 5*time.Minute || *expectedStatus < 100 || *expectedStatus > 599 {
		panic("invalid load budget")
	}
	var body []byte
	contentType, method, path, ua := "", "GET", "/asset.txt", "WAF-performance-fixture/1.0"
	switch *workload {
	case "static":
	case "sse":
		path = "/sse"
	case "json", "json64", "attack-json":
		length := 1024
		if *workload != "json" {
			length = 64 << 10
		}
		body = []byte(`{"title":"Performance fixture","description":"` + strings.Repeat("ordinary content ", length/17) + `","count":2}`)
		contentType, method, path = "application/json", "POST", "/api/echo"
		if *workload == "attack-json" {
			ua = "sqlmap/1.8"
		}
	case "upload", "attack":
		var b bytes.Buffer
		m := multipart.NewWriter(&b)
		part, err := m.CreateFormFile("file", "sample.txt")
		if err != nil {
			panic(err)
		}
		_, _ = io.CopyN(part, strings.NewReader(strings.Repeat("A", 1<<20)), 1<<20)
		if err := m.Close(); err != nil {
			panic(err)
		}
		body, contentType, method, path = b.Bytes(), m.FormDataContentType(), "POST", "/api/echo"
		if *workload == "attack" {
			ua = "sqlmap/1.8"
		}
	default:
		panic("unknown workload")
	}
	tr := &http.Transport{MaxIdleConns: *concurrency, MaxIdleConnsPerHost: *concurrency, MaxConnsPerHost: *concurrency, IdleConnTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true}
	url := "http://fixture" + path
	if *target == "unix" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", *sock)
		}
	} else if *target == "tls" {
		pem, err := os.ReadFile("/test/cert.pem")
		if err != nil {
			panic(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			panic("invalid local certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
		tr.ForceAttemptHTTP2 = true
		tr.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			if address != "127.0.0.1:18443" {
				return nil, fmt.Errorf("non-loopback target refused")
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
		}
		url = "https://127.0.0.1:18443" + path
	} else {
		panic("unsupported target")
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	stats := totals{Codes: make(map[int]int64), Protocols: make(map[string]int64)}
	var sequence atomic.Int64
	request := func(scheduled time.Time) {
		i := sequence.Add(1)
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			panic(err)
		}
		prefix := "direct"
		if *identity == "proxy" {
			prefix = "proxy"
			req.Header.Set("CF-Connecting-IP", fmt.Sprintf("198.18.%d.%d", (i/250)%4, i%250+1))
		}
		req.Host = prefix + strconv.Itoa(int(i%int64(*hosts))) + ".example"
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		start := time.Now()
		resp, err := client.Do(req)
		var n int64
		code := 0
		proto := ""
		if err == nil {
			code, proto = resp.StatusCode, resp.Proto
			n, err = io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if err == nil {
				err = closeErr
			}
		}
		end := time.Now()
		stats.Lock()
		stats.Count++
		stats.Bytes += n
		stats.Codes[code]++
		stats.Protocols[proto]++
		if err != nil {
			stats.Errors++
		}
		stats.Histogram[bucket(end.Sub(scheduled))]++
		stats.ServiceHistogram[bucket(end.Sub(start))]++
		stats.Unlock()
	}
	start := time.Now()
	end := start.Add(*duration)
	var wg sync.WaitGroup
	if *rate == 0 {
		for i := 0; i < *concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(end) {
					request(time.Now())
				}
			}()
		}
		wg.Wait()
	} else {
		jobs := make(chan time.Time, *concurrency)
		for i := 0; i < *concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for at := range jobs {
					request(at)
				}
			}()
		}
		for i := int64(0); ; i++ {
			at := start.Add(time.Duration(i) * time.Second / time.Duration(*rate))
			if !at.Before(end) {
				break
			}
			if delay := time.Until(at); delay > 0 {
				time.Sleep(delay)
			}
			select {
			case jobs <- at:
			default:
				stats.Skipped++
			}
		}
		close(jobs)
		wg.Wait()
		if delay := time.Until(end); delay > 0 {
			time.Sleep(delay)
		}
	}
	elapsed := time.Since(start).Seconds()
	expected := *expectedStatus
	result := map[string]any{"workload": *workload, "target": *target, "identity": *identity, "hosts": *hosts, "concurrency": *concurrency, "targetRps": *rate, "durationSeconds": duration.Seconds(), "elapsedSeconds": elapsed, "requests": stats.Count, "completedRps": float64(stats.Count) / elapsed, "expectedStatus": expected, "expectedResponses": stats.Codes[expected], "networkErrors": stats.Errors, "skipped": stats.Skipped, "codes": stats.Codes, "protocols": stats.Protocols, "p50Ms": percentile(&stats.Histogram, stats.Count, .50), "p95Ms": percentile(&stats.Histogram, stats.Count, .95), "p99Ms": percentile(&stats.Histogram, stats.Count, .99), "serviceP99Ms": percentile(&stats.ServiceHistogram, stats.Count, .99), "responseBytes": stats.Bytes, "requestBodyBytes": len(body)}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
