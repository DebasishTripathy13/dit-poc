package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// runNetem measures handshake completion time (TCP connect plus TLS
// handshake, at the client) under emulated network conditions. It must run in
// a private network namespace with CAP_NET_ADMIN (unshare -rn): it sets the
// loopback MTU to 1500 bytes, so that TCP segment sizes and the initial
// congestion window are those of an Ethernet path, and applies tc netem on
// loopback with a one-way delay of RTT/2 and the configured loss in each
// direction. Client and server run on the same machine.
func runNetem() {
	sh := func(args ...string) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			check(fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out))
		}
	}
	sh("ip", "link", "set", "lo", "up")
	sh("ip", "link", "set", "lo", "mtu", "1500")
	_, t, stop := startServer()
	defer stop()
	defer exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()

	want := map[string]bool{"a_tls13_classical": true, "b_tls13_hybrid_kem": true, "bp_ours_hybrid_ecdsa": true,
		"c_tls13_full_pq": true, "dit_warm": true, "dit_warm_new_epoch": true, "dit_cold": true}
	var rows, samples [][]string
	for _, rs := range strings.Split(*flagNetem, ",") {
		rtt, err := strconv.ParseFloat(strings.TrimSpace(rs), 64)
		check(err)
		sh("tc", "qdisc", "replace", "dev", "lo", "root", "netem",
			"delay", fmt.Sprintf("%gms", rtt/2), "loss", fmt.Sprintf("%g%%", *flagNetemLoss), "limit", "100000")
		for _, v := range variants(t) {
			if !want[v.name] {
				continue
			}
			addr := fmt.Sprintf("127.0.0.1:%d", t.Ports[v.port])
			one := func() (time.Duration, error) {
				start := time.Now()
				c, err := net.Dial("tcp", addr)
				if err != nil {
					return 0, err
				}
				defer c.Close()
				if _, err := v.dial(c); err != nil {
					return 0, err
				}
				return time.Since(start), nil
			}
			for i := 0; i < 20; i++ { // warm-up
				one()
			}
			lat := make([]time.Duration, 0, *flagNetemN)
			var mu sync.Mutex
			var wg sync.WaitGroup
			next := 0
			for g := 0; g < *flagNetemConc; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						mu.Lock()
						if next >= *flagNetemN {
							mu.Unlock()
							return
						}
						next++
						mu.Unlock()
						d, err := one()
						check(err)
						mu.Lock()
						lat = append(lat, d)
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			for i, d := range lat {
				samples = append(samples, []string{v.name, rs, strconv.Itoa(i), strconv.FormatInt(int64(d), 10)})
			}
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			var sum time.Duration
			for _, d := range lat {
				sum += d
			}
			ms := func(d time.Duration) string { return strconv.FormatFloat(float64(d)/1e6, 'f', 2, 64) }
			p50 := pct(lat, .5)
			rows = append(rows, []string{v.name, rs, strconv.FormatFloat(*flagNetemLoss, 'f', 2, 64),
				strconv.Itoa(len(lat)), ms(p50), ms(pct(lat, .95)), ms(pct(lat, .99)), ms(sum / time.Duration(len(lat))),
				strconv.FormatFloat(float64(p50)/1e6/rtt, 'f', 2, 64)})
			fmt.Fprintf(os.Stderr, "rtt %5s ms  %-24s p50 %8s ms  (%.2f RTT)\n", rs, v.name, ms(p50), float64(p50)/1e6/rtt)
		}
	}
	writeCSV(filepath.Join(*flagOut, "netem.csv"), []string{"variant", "rtt_ms", "loss_pct", "n",
		"p50_ms", "p95_ms", "p99_ms", "mean_ms", "p50_in_rtts"}, rows)
	writeCSV(filepath.Join(*flagOut, "netem_samples.csv"), []string{"variant", "rtt_ms", "i", "latency_ns"}, samples)
}
