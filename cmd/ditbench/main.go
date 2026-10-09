// Command ditbench produces every number in the paper's performance section.
//
//	go run ./cmd/ditbench -out results
//
// It writes, into -out:
//
//	env.csv              machine, toolchain and parameters of the run
//	primitives.csv       microbenchmarks of every primitive (testing.Benchmark)
//	sizes.csv            encoded size of every DIT object (TLV and JSON)
//	handshakes.csv       per variant: bytes on the wire, signature
//	                     verifications, latency percentiles, client CPU, server
//	                     CPU per handshake and single-core handshakes/s
//	latency_samples.csv  every individual handshake latency
//
// The server runs in a child process pinned to one logical CPU with
// GOMAXPROCS=1; clients run in this process on the remaining CPUs. All
// traffic is over TCP on the loopback interface: no network latency or loss
// is emulated, so latencies are computation plus loopback cost only.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dit-protocol/poc/baseline"
	"github.com/dit-protocol/poc/handshake"
	"github.com/dit-protocol/poc/identity"
	"github.com/dit-protocol/poc/sim"
)

var (
	flagOut       = flag.String("out", "results", "output directory")
	flagN         = flag.Int("n", 10000, "measured sequential handshakes per variant")
	flagWarmup    = flag.Int("warmup", 1000, "warm-up handshakes per variant (discarded)")
	flagTput      = flag.Duration("tput", 5*time.Second, "duration of each throughput window")
	flagTputReps  = flag.Int("tput-reps", 3, "throughput windows per variant (median reported)")
	flagConc      = flag.Int("conc", 12, "concurrent clients in throughput runs")
	flagServerCPU = flag.Int("server-cpu", 4, "logical CPU the server process is pinned to")
	flagClientCPU = flag.String("client-cpus", "0-3,6-19", "logical CPUs for the load generator")
	flagLogSize   = flag.Int("log-size", 1<<20, "number of entries in the simulated DIT log")
	flagBenchTime = flag.Duration("benchtime", time.Second, "target time per primitive microbenchmark")
	flagServe     = flag.Bool("serve", false, "internal: run as the pinned server process")
	flagOnly      = flag.String("only", "", "run only one stage: primitives, sizes or handshakes")
)

func main() {
	flag.Parse()
	if *flagServe {
		if err := serve(*flagLogSize); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	// Re-execute under taskset so that every thread of the load generator
	// stays off the server's CPU.
	if os.Getenv("DITBENCH_PINNED") == "" && *flagClientCPU != "" {
		if ts, err := exec.LookPath("taskset"); err == nil {
			self, _ := os.Executable()
			args := append([]string{ts, "-c", *flagClientCPU, self}, os.Args[1:]...)
			env := append(os.Environ(), "DITBENCH_PINNED=1")
			check(syscall.Exec(ts, args, env))
		}
		fmt.Fprintln(os.Stderr, "warning: taskset not found; CPU pinning disabled")
	}
	check(os.MkdirAll(*flagOut, 0o755))
	stage := func(name string) bool { return *flagOnly == "" || *flagOnly == name }
	if *flagOnly == "" {
		writeEnv()
	}
	if stage("primitives") {
		fmt.Fprintln(os.Stderr, "== primitives")
		runPrimitives(filepath.Join(*flagOut, "primitives.csv"))
	}
	if stage("sizes") {
		fmt.Fprintln(os.Stderr, "== sizes")
		runSizes(filepath.Join(*flagOut, "sizes.csv"))
	}
	if stage("handshakes") {
		fmt.Fprintln(os.Stderr, "== handshakes")
		runHandshakes()
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ditbench:", err)
		os.Exit(1)
	}
}

func writeCSV(path string, header []string, rows [][]string) {
	f, err := os.Create(path)
	check(err)
	defer f.Close()
	w := csv.NewWriter(f)
	check(w.Write(header))
	check(w.WriteAll(rows))
}

func writeEnv() {
	cpu := "unknown"
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "model name") {
				cpu = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
				break
			}
		}
	}
	kernel := "unknown"
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(b))
	}
	commit := "unknown"
	if b, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(b))
	}
	rows := [][]string{
		{"date_utc", time.Now().UTC().Format(time.RFC3339)},
		{"git_commit", commit},
		{"go_version", runtime.Version()},
		{"os_arch", runtime.GOOS + "/" + runtime.GOARCH},
		{"kernel", kernel},
		{"cpu_model", cpu},
		{"logical_cpus", strconv.Itoa(runtime.NumCPU())},
		{"server_cpu", strconv.Itoa(*flagServerCPU)},
		{"client_cpus", *flagClientCPU},
		{"transport", "TCP over loopback (127.0.0.1), no netem"},
		{"handshakes_measured", strconv.Itoa(*flagN)},
		{"handshakes_warmup", strconv.Itoa(*flagWarmup)},
		{"throughput_seconds", flagTput.String()},
		{"throughput_windows", strconv.Itoa(*flagTputReps)},
		{"throughput_concurrency", strconv.Itoa(*flagConc)},
		{"dit_log_size", strconv.Itoa(*flagLogSize)},
		{"witness_policy", fmt.Sprintf("%d-of-%d", sim.Quorum, sim.Witnesses)},
		{"recovery_policy", fmt.Sprintf("%d-of-%d", sim.PeersT, sim.PeersN)},
	}
	writeCSV(filepath.Join(*flagOut, "env.csv"), []string{"key", "value"}, rows)
}

// ─── Handshake variants ───────────────────────────────────────────────────────

type variant struct {
	name, port, desc string
	dial             func(net.Conn) (verifies int, err error)
}

func variants(t *trust) []variant {
	now := time.Unix(t.Now, 0)
	root, err := x509.ParseCertificate(t.ECDSARoot)
	check(err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	tlsClient := func(v baseline.Variant) func(net.Conn) (int, error) {
		return func(c net.Conn) (int, error) {
			cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: sim.Domain,
				SessionTicketsDisabled: true, Time: func() time.Time { return now }}
			cfg.CurvePreferences = []tls.CurveID{tls.X25519}
			if v == baseline.HybridKEM {
				cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
			}
			// Chain: leaf by intermediate, intermediate by root, CertificateVerify.
			return 3, tls.Client(c, cfg).Handshake()
		}
	}
	id, err := identity.UnmarshalIdentityTLV(t.Identity)
	check(err)
	cred, err := identity.UnmarshalCredentialTLV(t.Credential)
	check(err)
	policy := handshake.WitnessPolicy{LogPub: t.LogPub, Witnesses: map[uint8][]byte{}, Q: sim.Quorum, MaxAge: 24 * time.Hour}
	for k, v := range t.Witnesses {
		policy.Witnesses[uint8(k)] = v
	}
	dit := func(pin, cached bool) func(net.Conn) (int, error) {
		return func(c net.Conn) (int, error) {
			cl := &handshake.DITClient{DNSCommitment: t.Commitment, Policy: policy, Now: func() time.Time { return now }}
			if pin {
				cl.Pin = id
			}
			if cached {
				cl.CachedCred = cred
			}
			_, err := handshake.Client(c, sim.Domain, cl)
			return cl.Verifies, err
		}
	}
	pq := func(c net.Conn) (int, error) {
		cl := &handshake.PQChainClient{RootPub: t.PQRoot, LogPubs: t.PQLogs}
		_, err := handshake.Client(c, sim.Domain, cl)
		return cl.Verifies, err
	}
	return []variant{
		{"a_tls13_classical", "a", "TLS 1.3, ECDSA P-256 chain, X25519 (crypto/tls)", tlsClient(baseline.Classical)},
		{"b_tls13_hybrid_kem", "b", "TLS 1.3, ECDSA P-256 chain, X25519MLKEM768 (crypto/tls)", tlsClient(baseline.HybridKEM)},
		{"c_tls13_full_pq", "c", "TLS 1.3, ML-DSA-65 chain + 2 ML-DSA SCTs, X25519MLKEM768", pq},
		{"dit_warm", "dit", "DIT, pinned identity, cached epoch credential", dit(true, true)},
		{"dit_warm_new_epoch", "dit", "DIT, pinned identity, new epoch credential", dit(true, false)},
		{"dit_cold", "dit", "DIT, first contact, TLV encoding", dit(false, false)},
		{"dit_warm_new_epoch_json", "dit-json", "DIT, pinned identity, new epoch credential, JSON encoding", dit(true, false)},
		{"dit_cold_json", "dit-json", "DIT, first contact, JSON encoding", dit(false, false)},
	}
}

func startServer() (*exec.Cmd, *trust, func()) {
	self, err := os.Executable()
	check(err)
	ts, err := exec.LookPath("taskset")
	var cmd *exec.Cmd
	args := []string{"-serve", "-log-size", strconv.Itoa(*flagLogSize)}
	if err == nil {
		cmd = exec.Command(ts, append([]string{"-c", strconv.Itoa(*flagServerCPU), self}, args...)...)
	} else {
		cmd = exec.Command(self, args...)
	}
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	check(err)
	stdout, err := cmd.StdoutPipe()
	check(err)
	check(cmd.Start())
	line, err := bufio.NewReader(stdout).ReadString('\n')
	check(err)
	t := &trust{}
	check(json.Unmarshal([]byte(line), t))
	return cmd, t, func() { stdin.Close(); _ = cmd.Wait() }
}

// procCPU returns user+system CPU time of a process from /proc/<pid>/stat.
func procCPU(pid int) time.Duration {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	check(err)
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	ut, _ := strconv.ParseInt(f[11], 10, 64)
	st, _ := strconv.ParseInt(f[12], 10, 64)
	return time.Duration(ut+st) * time.Second / 100 // USER_HZ = 100 on Linux
}

func selfCPU() time.Duration {
	var ru syscall.Rusage
	check(syscall.Getrusage(syscall.RUSAGE_SELF, &ru))
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func pct(sorted []time.Duration, p float64) time.Duration {
	i := int(p*float64(len(sorted)-1) + 0.5)
	return sorted[i]
}

func us(d time.Duration) string { return strconv.FormatFloat(float64(d)/1e3, 'f', 1, 64) }

func runHandshakes() {
	cmd, t, stop := startServer()
	defer stop()
	header := []string{"variant", "description", "client_to_server_bytes", "server_to_client_bytes", "total_bytes",
		"client_sig_verifications", "n", "latency_p50_us", "latency_p95_us", "latency_p99_us", "latency_mean_us",
		"client_cpu_us_per_hs", "server_cpu_us_per_hs", "server_cpu_us_per_hs_min", "server_cpu_us_per_hs_max",
		"server_hs_per_s_single_core", "server_cpu_utilization", "throughput_hs"}
	var rows, samples [][]string
	for _, v := range variants(t) {
		addr := fmt.Sprintf("127.0.0.1:%d", t.Ports[v.port])
		one := func() (time.Duration, *handshake.CountingConn, int) {
			raw, err := net.Dial("tcp", addr)
			check(err)
			c := &handshake.CountingConn{Conn: raw}
			start := time.Now()
			ver, err := v.dial(c)
			d := time.Since(start)
			check(err)
			raw.Close()
			return d, c, ver
		}
		// Bytes and verification count from one handshake.
		_, cc, ver := one()
		fmt.Fprintf(os.Stderr, "%-26s %6d B up %6d B down\n", v.name, cc.BytesWritten, cc.BytesRead)
		for i := 0; i < *flagWarmup; i++ {
			one()
		}
		lat := make([]time.Duration, *flagN)
		cpu0 := selfCPU()
		for i := range lat {
			lat[i], _, _ = one()
			samples = append(samples, []string{v.name, strconv.Itoa(i), strconv.FormatInt(int64(lat[i]), 10)})
		}
		clientCPU := (selfCPU() - cpu0) / time.Duration(*flagN)
		var sum time.Duration
		for _, d := range lat {
			sum += d
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

		// Throughput: saturate the single-core server, in several windows.
		type window struct {
			perHS time.Duration
			rate  float64
			util  float64
			n     int64
		}
		var ws []window
		for rep := 0; rep < *flagTputReps; rep++ {
			var done atomic.Int64
			stopAt := time.Now().Add(*flagTput)
			srv0 := procCPU(cmd.Process.Pid)
			t0 := time.Now()
			var wg sync.WaitGroup
			for g := 0; g < *flagConc; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for time.Now().Before(stopAt) {
						raw, err := net.Dial("tcp", addr)
						if err != nil {
							continue
						}
						if _, err := v.dial(raw); err == nil {
							done.Add(1)
						}
						raw.Close()
					}
				}()
			}
			wg.Wait()
			elapsed := time.Since(t0)
			srvCPU := procCPU(cmd.Process.Pid) - srv0
			n := done.Load()
			ws = append(ws, window{srvCPU / time.Duration(n), float64(n) / elapsed.Seconds(),
				srvCPU.Seconds() / elapsed.Seconds(), n})
		}
		sort.Slice(ws, func(i, j int) bool { return ws[i].perHS < ws[j].perHS })
		med := ws[len(ws)/2]
		rows = append(rows, []string{v.name, v.desc, strconv.Itoa(cc.BytesWritten), strconv.Itoa(cc.BytesRead),
			strconv.Itoa(cc.BytesWritten + cc.BytesRead), strconv.Itoa(ver), strconv.Itoa(*flagN),
			us(pct(lat, .50)), us(pct(lat, .95)), us(pct(lat, .99)), us(sum / time.Duration(*flagN)),
			us(clientCPU), us(med.perHS), us(ws[0].perHS), us(ws[len(ws)-1].perHS),
			strconv.FormatFloat(med.rate, 'f', 0, 64), strconv.FormatFloat(med.util, 'f', 3, 64),
			strconv.FormatInt(med.n, 10)})
		fmt.Fprintf(os.Stderr, "%-26s p50 %s us, server %s us/hs [%s-%s], %.0f hs/s\n", v.name, us(pct(lat, .5)),
			us(med.perHS), us(ws[0].perHS), us(ws[len(ws)-1].perHS), med.rate)
	}
	writeCSV(filepath.Join(*flagOut, "handshakes.csv"), header, rows)
	writeCSV(filepath.Join(*flagOut, "latency_samples.csv"), []string{"variant", "i", "latency_ns"}, samples)
}
