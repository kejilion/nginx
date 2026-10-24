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
	Encodings                     map[string]int64
	Histogram                     [1200001]int64 // 100 us buckets, capped at two minutes.
	ServiceHistogram              [1200001]int64
}

func bucket(d time.Duration) int {
	n := int(d / (100 * time.Microsecond))
	if n > 1200000 {
		return 1200000
	}
	return n
}
func percentile(h *[1200001]int64, count int64, p float64) float64 {
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
	return 120000
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
	large, _ := os.ReadFile("/test/large.txt")
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
			if r.URL.Path == "/large.txt" && len(large) > 0 {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", strconv.Itoa(len(large)))
				_, _ = w.Write(large)
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
	requestPath := flag.String("path", "", "override the fixture request path")
	encoding := flag.String("encoding", "", "explicit Accept-Encoding")
	readRate := flag.Int("read-kib", 0, "bounded slow-reader speed, KiB/s; 0=unlimited")
	http1 := flag.Bool("http1", false, "disable HTTP/2 for TLS fixture")
	timeout := flag.Duration("timeout", 5*time.Second, "request timeout, at most two minutes")
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
	if *requestPath != "" {
		if !strings.HasPrefix(*requestPath, "/") {
			panic("path must be relative to fixture")
		}
		path = *requestPath
	}
	if *readRate < 0 || *readRate > 16384 {
		panic("invalid read budget")
	}
	if *timeout < time.Second || *timeout > 2*time.Minute {
		panic("invalid timeout")
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
		if *http1 {
			tr.ForceAttemptHTTP2 = false
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
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
	client := &http.Client{Transport: tr, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	stats := totals{Codes: make(map[int]int64), Protocols: make(map[string]int64), Encodings: make(map[string]int64)}
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
		if *encoding != "" {
			req.Header.Set("Accept-Encoding", *encoding)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		start := time.Now()
		resp, err := client.Do(req)
		var n int64
		code := 0
		proto := ""
		contentEncoding := ""
		if err == nil {
			code, proto = resp.StatusCode, resp.Proto
			contentEncoding = resp.Header.Get("Content-Encoding")
			if *readRate == 0 {
				n, err = io.Copy(io.Discard, resp.Body)
			} else {
				buffer := make([]byte, 16384)
				readStart := time.Now()
				for {
					count, readErr := resp.Body.Read(buffer)
					n += int64(count)
					if readErr != nil {
						if readErr != io.EOF {
							err = readErr
						}
						break
					}
					if delay := time.Duration(n)*time.Second/time.Duration(*readRate*1024) - time.Since(readStart); delay > 0 {
						time.Sleep(delay)
					}
				}
			}
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
		stats.Encodings[contentEncoding]++
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
	result["encodings"] = stats.Encodings
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
