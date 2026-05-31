// single-connection CF clean-IP scanner prototype.
//
// One TCP+TLS1.3 connection per IP. Inside that connection: send GET to a
// grey-SNI firehose worker (set via -worker-host and -get-path), slice the
// response bytes into 250ms buckets for stream-secs, classify:
//
//	dead             : <4KB total — TCP/TLS handshook but no usable burst
//	gray             : burst landed in bucket 0 but buckets 1+ all <4KB
//	                   (the E74 gray-cap: ~6-packet ceiling on grey SNI)
//	clean-candidate  : >=ceil((N-1)/2) of buckets 1..N-1 carry >=4KB
//	partial          : neither, ambiguous
//
// Candidates run a verify pass: spaced re-dials to filter out IPs that
// "ghost" on second connect (the stage-0→stage-1 22% blackhole tier).
//
// confirms loc=IR via /cdn-cgi/trace on a hardcoded CF IP (no DNS).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bump when the output wire format changes (new Row/Meta fields, semantic
// shifts in verdicts, etc.). Helpers' JSONL is joinable across runs only
// if the tool_version matches — different versions imply re-analysis.
const toolVersion = "s9-cfscan-proto-2026-05-31-cidr"

type config struct {
	targets         string
	workerHost      string
	getPath         string
	preflightIP     string
	skipPreflight   bool
	dialTO          time.Duration
	tlsTO           time.Duration
	firstByteTO     time.Duration
	streamSecs      float64
	bucketMS        int
	concurrency     int
	skip24After     int
	verify          bool
	verifyIntervals string
	verifyPassMin   int
	noShuffle       bool
	shuffleSeed     int64
	out             string
}

type Row struct {
	IP          string  `json:"ip"`
	Stage       string  `json:"stage"`
	DelaySecs   float64 `json:"delay_secs,omitempty"`
	TCPOK       bool    `json:"tcp_ok"`
	TLSOK       bool    `json:"tls_ok"`
	HTTPCode    int     `json:"http_code,omitempty"`
	ServerHdr   string  `json:"server,omitempty"`
	TotalBytes  int     `json:"total_bytes"`
	BucketMS    int     `json:"bucket_ms"`
	Buckets     []int   `json:"buckets"`
	Verdict     string  `json:"verdict"`
	Err         string  `json:"err,omitempty"`
	RTTMs       int64   `json:"rtt_ms"`        // TCP dial RTT (-1 = TCP failed)
	TLSMs       int64   `json:"tls_ms"`        // TLS handshake duration (-1 = not reached)
	FirstByteMS int64   `json:"first_byte_ms"` // GET-write -> first byte arrival (-1 = never)
	UnixMS      int64   `json:"unix_ms"`
}

// Meta is emitted as the FIRST line of every output file. Distinguished
// from probe Rows by `kind="meta"` (Rows have no kind field). Analysis
// scripts should skip it: `if r.get("kind") == "meta": continue`.
type Meta struct {
	Kind            string  `json:"kind"` // always "meta"
	ToolVersion     string  `json:"tool_version"`
	HostOS          string  `json:"host_os"`
	HostArch        string  `json:"host_arch"`
	UnixMSStart     int64   `json:"unix_ms_start"`
	WorkerHost      string  `json:"worker_host"`
	GetPath         string  `json:"get_path"`
	DialTO          string  `json:"dial_to"`
	TLSTo           string  `json:"tls_to"`
	FirstByteTO     string  `json:"first_byte_to"`
	StreamSecs      float64 `json:"stream_secs"`
	BucketMS        int     `json:"bucket_ms"`
	Concurrency     int     `json:"c"`
	Skip24After     int     `json:"skip_24_after"`
	VerifyIntervals string  `json:"verify_intervals"`
	VerifyPassMin   int     `json:"verify_pass_min"`
	PreflightIP     string  `json:"preflight_ip"`
	SkipPreflight   bool    `json:"skip_preflight"`
	NTargets        int     `json:"n_targets"`
	NInputLines     int     `json:"n_input_lines"`
	NCIDRs          int     `json:"n_cidrs"`
	Shuffled        bool    `json:"shuffled"`
	ShuffleSeed     int64   `json:"shuffle_seed"`
	TargetsPath     string  `json:"targets_path"`
}

func main() {
	var cfg config
	flag.StringVar(&cfg.targets, "targets", "", "file with IPs, one per line (required)")
	flag.StringVar(&cfg.workerHost, "worker-host", "", "SNI + Host header (must be a grey CF worker domain) (required)")
	flag.StringVar(&cfg.getPath, "get-path", "/stream", "path for firehose worker GET")
	flag.StringVar(&cfg.preflightIP, "preflight-ip", "104.19.229.21", "CF IP for loc=IR preflight (avoid DNS; '' disables IP-side dial but still requires preflight)")
	flag.BoolVar(&cfg.skipPreflight, "skip-preflight", false, "skip loc=IR preflight check (DANGEROUS — confirm ir-run vantage yourself)")
	flag.DurationVar(&cfg.dialTO, "dial-to", 500*time.Millisecond, "TCP dial timeout (E58: 500ms is aggressive; bump to 1.2s for recall)")
	flag.DurationVar(&cfg.tlsTO, "tls-to", 1500*time.Millisecond, "TLS handshake + write deadline budget")
	flag.DurationVar(&cfg.firstByteTO, "first-byte-to", 400*time.Millisecond, "max wait for the FIRST response byte after GET (early-aborts starved IPs; 0 disables and keeps full stream window)")
	flag.Float64Var(&cfg.streamSecs, "stream-secs", 1.5, "byte-read window after first byte arrives (s); >=2 buckets recommended")
	flag.IntVar(&cfg.bucketMS, "bucket-ms", 250, "bucket width (ms)")
	flag.IntVar(&cfg.concurrency, "c", 64, "concurrent probes (S5 knee = 64; raise w/ care)")
	flag.IntVar(&cfg.skip24After, "skip-24-after", 5, "skip remaining IPs in a /24 after N starved/gray/partial hits in it (preserves sparse /24s where clean IPs live; 0 disables)")
	flag.BoolVar(&cfg.verify, "verify", true, "run verify pass on clean-candidate IPs")
	flag.StringVar(&cfg.verifyIntervals, "verify-intervals", "30s,60s,2m,5m,10m", "spaced sleep durations before each verify retry")
	flag.IntVar(&cfg.verifyPassMin, "verify-pass-min", 4, "minimum clean-candidate verdicts in verify pass to call CLEAN")
	flag.BoolVar(&cfg.noShuffle, "no-shuffle", false, "scan IPs in input order (default: Fisher-Yates shuffle across the entire expanded target set, masscan-style anti-clustering so we don't hammer a single /24 sequentially)")
	flag.Int64Var(&cfg.shuffleSeed, "shuffle-seed", 0, "RNG seed for the shuffle (0 = time-based; set for reproducible order across reruns)")
	flag.StringVar(&cfg.out, "out", "cfscan_proto.jsonl", "output JSONL")
	flag.Parse()

	if cfg.targets == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -targets is required")
		os.Exit(2)
	}
	if strings.TrimSpace(cfg.workerHost) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -worker-host is required")
		os.Exit(2)
	}

	if !cfg.skipPreflight {
		if err := preflight(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "PREFLIGHT FAILED: %v\nset -skip-preflight to override (only if you've confirmed ir-run yourself)\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "preflight: loc=IR ok")
	}

	targets, nLines, nCIDR, err := loadTargets(cfg.targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load targets: %v\n", err)
		os.Exit(1)
	}
	shuffleSeed := cfg.shuffleSeed
	if !cfg.noShuffle {
		if shuffleSeed == 0 {
			shuffleSeed = time.Now().UnixNano()
		}
		shuffleIPs(targets, shuffleSeed)
	}
	fmt.Fprintf(os.Stderr, "loaded %d targets from %d lines (%d CIDRs), c=%d, dial-to=%v, first-byte-to=%v, stream-secs=%.1fs, skip-24-after=%d, shuffle=%v(seed=%d), sni=%s%s\n",
		len(targets), nLines, nCIDR, cfg.concurrency, cfg.dialTO, cfg.firstByteTO, cfg.streamSecs, cfg.skip24After,
		!cfg.noShuffle, shuffleSeed, cfg.workerHost, cfg.getPath)

	f, err := os.Create(cfg.out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var outMu sync.Mutex
	emit := func(r Row) {
		r.UnixMS = time.Now().UnixMilli()
		outMu.Lock()
		defer outMu.Unlock()
		b, _ := json.Marshal(r)
		f.Write(b)
		f.Write([]byte("\n"))
	}

	// Emit the meta header line FIRST so helpers' files are self-describing.
	meta := Meta{
		Kind:            "meta",
		ToolVersion:     toolVersion,
		HostOS:          runtime.GOOS,
		HostArch:        runtime.GOARCH,
		UnixMSStart:     time.Now().UnixMilli(),
		WorkerHost:      cfg.workerHost,
		GetPath:         cfg.getPath,
		DialTO:          cfg.dialTO.String(),
		TLSTo:           cfg.tlsTO.String(),
		FirstByteTO:     cfg.firstByteTO.String(),
		StreamSecs:      cfg.streamSecs,
		BucketMS:        cfg.bucketMS,
		Concurrency:     cfg.concurrency,
		Skip24After:     cfg.skip24After,
		VerifyIntervals: cfg.verifyIntervals,
		VerifyPassMin:   cfg.verifyPassMin,
		PreflightIP:     cfg.preflightIP,
		SkipPreflight:   cfg.skipPreflight,
		NTargets:        len(targets),
		NInputLines:     nLines,
		NCIDRs:          nCIDR,
		Shuffled:        !cfg.noShuffle,
		ShuffleSeed:     shuffleSeed,
		TargetsPath:     cfg.targets,
	}
	if mb, err := json.Marshal(meta); err == nil {
		f.Write(mb)
		f.Write([]byte("\n"))
	}

	// ---- main pass ----
	fmt.Fprintln(os.Stderr, "main pass start")
	var done atomic.Int64
	var tcpDeadCt, tlsFailCt, starvedCt, grayCt, candCt, partialCt, skippedCt atomic.Int64
	candidates := make([]string, 0)
	var candMu sync.Mutex

	// Progress state. When stderr is a terminal, render an in-place bar
	// every second; otherwise append plain status lines. Either way,
	// clean-candidate IPs print immediately on their own line so the
	// human can start verifying them manually while the scan runs.
	progressTTY := isTerminal(os.Stderr)
	var progMu sync.Mutex
	var lastLineLen int
	startT := time.Now()
	clearLine := func() {
		if progressTTY && lastLineLen > 0 {
			fmt.Fprint(os.Stderr, "\r", strings.Repeat(" ", lastLineLen), "\r")
			lastLineLen = 0
		}
	}
	renderProgress := func() {
		d := done.Load()
		elapsed := time.Since(startT).Seconds()
		rate := 0.0
		if elapsed > 0 {
			rate = float64(d) / elapsed
		}
		remaining := int64(len(targets)) - d
		eta := "?"
		if rate > 0 && remaining > 0 {
			s := time.Duration(float64(remaining) / rate * float64(time.Second))
			switch {
			case s >= time.Hour:
				eta = fmt.Sprintf("%dh%02dm", int(s.Hours()), int(s.Minutes())%60)
			case s >= time.Minute:
				eta = fmt.Sprintf("%dm%02ds", int(s.Minutes()), int(s.Seconds())%60)
			default:
				eta = fmt.Sprintf("%ds", int(s.Seconds()))
			}
		}
		pct := 0.0
		if len(targets) > 0 {
			pct = 100 * float64(d) / float64(len(targets))
		}
		barW := 24
		fill := int(pct / 100 * float64(barW))
		if fill > barW {
			fill = barW
		}
		bar := strings.Repeat("#", fill) + strings.Repeat(".", barW-fill)
		line := fmt.Sprintf("[%s] %5.1f%% %d/%d  %4.0f IPs/s  ETA %-7s  dead=%d strv=%d gray=%d cand=%d skip=%d",
			bar, pct, d, len(targets), rate, eta,
			tcpDeadCt.Load(), starvedCt.Load(), grayCt.Load(), candCt.Load(), skippedCt.Load())

		progMu.Lock()
		defer progMu.Unlock()
		if progressTTY {
			if len(line) < lastLineLen {
				line += strings.Repeat(" ", lastLineLen-len(line))
			}
			fmt.Fprint(os.Stderr, "\r", line)
			lastLineLen = len(line)
		} else {
			// non-TTY: append-only every render
			fmt.Fprintln(os.Stderr, line)
		}
	}
	printCandidate := func(r Row) {
		progMu.Lock()
		defer progMu.Unlock()
		clearLine()
		fmt.Fprintf(os.Stderr,
			"[CANDIDATE] %-15s  total=%dKB  rtt=%dms  tls=%dms  first=%dms  http=%d  buckets=%v\n",
			r.IP, r.TotalBytes/1024, r.RTTMs, r.TLSMs, r.FirstByteMS, r.HTTPCode, r.Buckets)
	}

	// Progress ticker — 1s in TTY (in-place), 30s otherwise (append).
	progStop := make(chan struct{})
	progDone := make(chan struct{})
	go func() {
		defer close(progDone)
		tickDur := time.Second
		if !progressTTY {
			tickDur = 30 * time.Second
		}
		t := time.NewTicker(tickDur)
		defer t.Stop()
		for {
			select {
			case <-progStop:
				return
			case <-t.C:
				renderProgress()
			}
		}
	}()

	// per-/24 unusable-hit counter; if it crosses cfg.skip24After we skip
	// remaining IPs in that /24. Counter is bumped only on starved/gray/
	// partial (i.e. "TLS admitted but unusable") — tcp-dead/tls-fail are
	// uninformative about the /24's classifier status; clean-candidate
	// never bumps because we want to keep probing that /24 fully.
	var satMap sync.Map
	bumpSat := func(prefix string) int32 {
		v, _ := satMap.LoadOrStore(prefix, &atomic.Int32{})
		return v.(*atomic.Int32).Add(1)
	}
	getSat := func(prefix string) int32 {
		v, ok := satMap.Load(prefix)
		if !ok {
			return 0
		}
		return v.(*atomic.Int32).Load()
	}

	jobs := make(chan string, cfg.concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				prefix := prefixOf(ip)
				if cfg.skip24After > 0 && getSat(prefix) >= int32(cfg.skip24After) {
					emit(Row{IP: ip, Stage: "main", Verdict: "skipped-24-saturated", BucketMS: cfg.bucketMS})
					skippedCt.Add(1)
					done.Add(1)
					continue
				}
				r := probe(cfg, ip, "main", 0)
				emit(r)
				switch r.Verdict {
				case "tcp-dead":
					tcpDeadCt.Add(1)
				case "tls-fail":
					tlsFailCt.Add(1)
				case "starved":
					starvedCt.Add(1)
					bumpSat(prefix)
				case "gray":
					grayCt.Add(1)
					bumpSat(prefix)
				case "clean-candidate":
					candCt.Add(1)
					candMu.Lock()
					candidates = append(candidates, ip)
					candMu.Unlock()
					printCandidate(r) // surface immediately so user can verify manually
				case "partial":
					partialCt.Add(1)
					bumpSat(prefix)
				}
				done.Add(1)
			}
		}()
	}

	t0 := time.Now()
	for _, ipU := range targets {
		jobs <- ipToStr(ipU)
	}
	close(jobs)
	wg.Wait()
	close(progStop)
	<-progDone
	progMu.Lock()
	clearLine()
	progMu.Unlock()
	mainDur := time.Since(t0)
	fmt.Fprintf(os.Stderr, "main pass DONE in %v\n", mainDur)
	fmt.Fprintf(os.Stderr, "  tcp-dead=%d tls-fail=%d starved=%d gray=%d clean-candidate=%d partial=%d skipped-24=%d\n",
		tcpDeadCt.Load(), tlsFailCt.Load(), starvedCt.Load(),
		grayCt.Load(), candCt.Load(), partialCt.Load(), skippedCt.Load())

	if !cfg.verify || len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "skipping verify pass (%d candidates, verify=%v)\n", len(candidates), cfg.verify)
		return
	}

	// ---- verify pass: parallel across candidates, sequential per candidate ----
	intervals := parseIntervals(cfg.verifyIntervals)
	if len(intervals) == 0 {
		fmt.Fprintln(os.Stderr, "no verify intervals parsed; skipping verify pass")
		return
	}
	fmt.Fprintf(os.Stderr, "verify pass: %d candidates × %d retries, intervals=%v\n",
		len(candidates), len(intervals), intervals)

	type verifyRes struct {
		IP     string
		Passes int
		Total  int
	}
	results := make([]verifyRes, 0, len(candidates))
	var rMu sync.Mutex
	var vwg sync.WaitGroup
	for _, ip := range candidates {
		vwg.Add(1)
		go func(ip string) {
			defer vwg.Done()
			passes := 0
			for i, d := range intervals {
				time.Sleep(d)
				r := probe(cfg, ip, fmt.Sprintf("verify-%d", i), d.Seconds())
				emit(r)
				if r.Verdict == "clean-candidate" {
					passes++
				}
				fmt.Fprintf(os.Stderr, "  %s verify-%d (slept %v): %s total=%d\n",
					ip, i, d, r.Verdict, r.TotalBytes)
			}
			rMu.Lock()
			results = append(results, verifyRes{IP: ip, Passes: passes, Total: len(intervals)})
			rMu.Unlock()
		}(ip)
	}
	vwg.Wait()

	fmt.Fprintln(os.Stderr, "\n=== verify results ===")
	cleanFinal := 0
	for _, v := range results {
		tag := "FAIL"
		if v.Passes >= cfg.verifyPassMin {
			tag = "CLEAN"
			cleanFinal++
		}
		fmt.Fprintf(os.Stderr, "  %s: %d/%d clean-passes → %s\n", v.IP, v.Passes, v.Total, tag)
	}
	fmt.Fprintf(os.Stderr, "\nFINAL: %d/%d candidates confirmed CLEAN (≥%d/%d passes)\n",
		cleanFinal, len(results), cfg.verifyPassMin, len(intervals))
}

// probe runs one full single-connection probe and returns a Row.
func probe(cfg config, ip, stage string, delay float64) (r Row) {
	r = Row{
		IP:          ip,
		Stage:       stage,
		DelaySecs:   delay,
		BucketMS:    cfg.bucketMS,
		RTTMs:       -1,
		TLSMs:       -1,
		FirstByteMS: -1,
	}
	defer func() { r.Verdict = classify(&r) }()

	totalBudget := cfg.dialTO + cfg.tlsTO + time.Duration(cfg.streamSecs*float64(time.Second)) + time.Second
	ctx, cancel := context.WithTimeout(context.Background(), totalBudget)
	defer cancel()

	d := net.Dialer{Timeout: cfg.dialTO}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		r.Err = "tcp:" + classifyErr(err)
		return r
	}
	defer conn.Close()
	r.TCPOK = true
	r.RTTMs = time.Since(t0).Milliseconds()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         cfg.workerHost,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(cfg.tlsTO))
	tlsStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		r.Err = "tls:" + classifyErr(err)
		return r
	}
	r.TLSMs = time.Since(tlsStart).Milliseconds()
	r.TLSOK = true

	req := "GET " + cfg.getPath + " HTTP/1.1\r\n" +
		"Host: " + cfg.workerHost + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Connection: close\r\n\r\n"

	streamDur := time.Duration(cfg.streamSecs * float64(time.Second))
	tlsConn.SetWriteDeadline(time.Now().Add(cfg.tlsTO))
	getWrittenAt := time.Now()
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		r.Err = "write:" + classifyErr(err)
		return r
	}

	bucketDur := time.Duration(cfg.bucketMS) * time.Millisecond
	nBuckets := int(streamDur / bucketDur)
	if nBuckets < 1 {
		nBuckets = 1
	}
	buckets := make([]int, nBuckets)

	// Two-phase read deadline (early-abort starved IPs):
	//   phase A (first-byte): wait at most cfg.firstByteTO for *any* byte.
	//     A real CF IP starts delivering well within ~RTT after the GET;
	//     a starved IP will sit at zero until the full stream window expires.
	//     If phase A times out with no bytes -> we exit immediately and the
	//     classifier sees total < floor -> verdict = "starved".
	//   phase B (full window): once any byte arrives, switch to the
	//     streamSecs deadline and slice the buckets normally.
	start := time.Now()
	deadline := start.Add(streamDur)
	if cfg.firstByteTO > 0 && cfg.firstByteTO < streamDur {
		tlsConn.SetReadDeadline(start.Add(cfg.firstByteTO))
	} else {
		tlsConn.SetReadDeadline(deadline.Add(50 * time.Millisecond))
	}
	gotFirstByte := false

	buf := make([]byte, 32*1024)
	var firstChunk []byte
	for {
		if time.Now().After(deadline) {
			break
		}
		n, rerr := tlsConn.Read(buf)
		if n > 0 {
			if !gotFirstByte {
				gotFirstByte = true
				r.FirstByteMS = time.Since(getWrittenAt).Milliseconds()
				// expand deadline to the full stream window now that we
				// know the IP is delivering bytes
				tlsConn.SetReadDeadline(deadline.Add(50 * time.Millisecond))
			}
			elapsed := time.Since(start)
			bi := int(elapsed / bucketDur)
			if bi >= nBuckets {
				bi = nBuckets - 1
			}
			buckets[bi] += n
			r.TotalBytes += n
			if len(firstChunk) < 1024 {
				want := 1024 - len(firstChunk)
				if want > n {
					want = n
				}
				firstChunk = append(firstChunk, buf[:want]...)
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				r.Err = "read:" + classifyErr(rerr)
			}
			break
		}
	}

	r.Buckets = buckets
	parseHTTPHead(firstChunk, &r)
	return r
}

// classify implements the E74 bucket rule, refined to split the pre-burst
// failure modes so we can distinguish tcp-dead / tls-fail / starved at
// scale. operationally all three are "unusable" but the mechanism differs.
func classify(r *Row) string {
	const floor = 4096
	if !r.TCPOK {
		return "tcp-dead"
	}
	if !r.TLSOK {
		return "tls-fail"
	}
	// TLS handshook. If we never got the burst, the censor admitted the
	// handshake but starved the application stream — a distinct tier from
	// gray (which delivers ~1 burst then zero).
	if r.TotalBytes < floor {
		return "starved"
	}
	if len(r.Buckets) < 2 {
		return "partial"
	}
	cleanCount := 0
	for i := 1; i < len(r.Buckets); i++ {
		if r.Buckets[i] >= floor {
			cleanCount++
		}
	}
	needed := (len(r.Buckets) - 1 + 1) / 2 // ceil((N-1)/2)
	if needed < 1 {
		needed = 1
	}
	if cleanCount >= needed {
		return "clean-candidate"
	}
	if r.Buckets[0] >= floor {
		return "gray"
	}
	return "partial"
}

func parseHTTPHead(b []byte, r *Row) {
	if len(b) == 0 {
		return
	}
	lines := strings.Split(string(b), "\r\n")
	if len(lines) == 0 {
		return
	}
	statusLine := lines[0]
	if strings.HasPrefix(statusLine, "HTTP/") {
		parts := strings.SplitN(statusLine, " ", 3)
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &r.HTTPCode)
		}
	}
	for _, line := range lines[1:] {
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "server:") {
			r.ServerHdr = strings.TrimSpace(line[len("server:"):])
			break
		}
	}
}

func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "connection reset"):
		return "rst"
	case strings.Contains(s, "no route to host"):
		return "no-route"
	case strings.Contains(s, "network is unreachable"):
		return "unreach"
	case strings.Contains(s, "broken pipe"):
		return "broken-pipe"
	}
	return s
}

func parseIntervals(s string) []time.Duration {
	out := make([]time.Duration, 0)
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		d, err := time.ParseDuration(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad verify interval %q: %v\n", p, err)
			continue
		}
		out = append(out, d)
	}
	return out
}

// prefixOf returns the /24 of an IPv4 dotted-quad as "a.b.c.0/24".
// Empty string on malformed input.
func prefixOf(ip string) string {
	a, b, c, d := 0, 0, 0, 0
	if _, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d); err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", a, b, c)
}

// loadTargets parses a target file that mixes bare IPv4 addresses and
// CIDR ranges (one per line; '#' starts a comment). Returns the
// expanded, deduped uint32 IP list plus diagnostic counts (number of
// non-blank input lines, number of CIDR lines).
//
// Storage is uint32 (4 B/IP) so 11M IPs ≈ 44 MB peak — fits comfortably
// on any machine. For >100M IPs (entire IPv4 sweep) a streaming
// Feistel cipher over ranges would be needed; not done here because
// our practical ceiling is ~30k CF /24s ≈ 7.7M IPs.
func loadTargets(path string) ([]uint32, int, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, err
	}
	out := make([]uint32, 0, 65536)
	nLines := 0
	nCIDR := 0
	for _, line := range strings.Split(string(b), "\n") {
		// strip inline trailing comments first ("a.b.c.d/24  # note")
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		nLines++
		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil || ipnet.IP.To4() == nil {
				continue
			}
			nCIDR++
			ip4 := ipnet.IP.To4()
			start := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
			ones, _ := ipnet.Mask.Size()
			count := uint64(1) << (32 - ones)
			for i := uint64(0); i < count; i++ {
				out = append(out, start+uint32(i))
			}
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil || ip.To4() == nil {
			continue
		}
		v4 := ip.To4()
		out = append(out, uint32(v4[0])<<24|uint32(v4[1])<<16|uint32(v4[2])<<8|uint32(v4[3]))
	}
	// dedupe via sort + in-place compaction
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if len(out) > 0 {
		j := 1
		for i := 1; i < len(out); i++ {
			if out[i] != out[i-1] {
				out[j] = out[i]
				j++
			}
		}
		out = out[:j]
	}
	return out, nLines, nCIDR, nil
}

// shuffleIPs Fisher-Yates shuffles in place. Wall-clock effect matches
// masscan's permutation cipher (probes spread across all /24s rather
// than sequential), at the cost of 4 B/IP storage we already paid.
func shuffleIPs(ips []uint32, seed int64) {
	r := mathrand.New(mathrand.NewSource(seed))
	for i := len(ips) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		ips[i], ips[j] = ips[j], ips[i]
	}
}

// ipToStr formats a uint32 IPv4 address as dotted-quad. Cheap enough
// to do per-dispatch (one fmt.Sprintf per probe, vs millions of bytes
// of string-cached targets).
func ipToStr(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// isTerminal reports whether f is connected to a terminal (i.e. not
// redirected to a file or pipe). Used to decide between in-place
// progress bar updates and append-only status lines.
func isTerminal(f *os.File) bool {
	s, err := f.Stat()
	if err != nil {
		return false
	}
	return (s.Mode() & os.ModeCharDevice) != 0
}

func preflight(cfg config) error {
	if cfg.preflightIP == "" {
		return fmt.Errorf("preflight-ip empty (set one or use -skip-preflight)")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(cfg.preflightIP, "443"))
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.preflightIP, err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "www.cloudflare.com",
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	req := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(tlsConn, 4096))
	loc := ""
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimSpace(line[4:])
		}
	}
	if loc != "IR" {
		return fmt.Errorf("loc=%q, want IR (run via ir-run)", loc)
	}
	return nil
}
