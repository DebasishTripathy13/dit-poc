# Reproduction targets. See README.md, section "Reproducing the paper".
PY ?= python3
RESULTS ?= results

.PHONY: all test bench bench-netem figures paper-artifacts quick formal clean-results

all: test

test:
	go vet ./...
	go test ./...
	go test -run='^$$' -bench=. -benchtime=5x ./bench/

# Full measurement run (about 10 minutes): writes $(RESULTS)/*.csv.
bench:
	go build -o bin/ditbench ./cmd/ditbench
	./bin/ditbench -out $(RESULTS)

# Network-emulation run (about 15 minutes): handshake completion time at
# 10/40/150 ms RTT with 0.1% loss, using tc netem on loopback inside an
# unprivileged user and network namespace (needs unshare and tc; no root).
bench-netem:
	go build -o bin/ditbench ./cmd/ditbench
	unshare -rn ./bin/ditbench -only netem -out $(RESULTS)

# Regenerate Table 1, Table 2, the appendix tables, the number macros and
# Figure 8 from the CSV files in $(RESULTS). Deterministic.
figures:
	$(PY) scripts/make_table1.py --results $(RESULTS) --out $(RESULTS)/generated
	$(PY) scripts/make_fig8.py --results $(RESULTS) --out $(RESULTS)/generated

paper-artifacts: bench bench-netem figures

# Small run used by CI (4-core runner).
quick:
	go build -o bin/ditbench ./cmd/ditbench
	./bin/ditbench -out results-ci -n 300 -warmup 30 -tput 2s -conc 3 \
		-benchtime 200ms -log-size 65536 -server-cpu 0 -client-cpus 1-3
	$(PY) scripts/make_table1.py --results results-ci --out results-ci/generated
	$(PY) scripts/make_fig8.py --results results-ci --out results-ci/generated

# Symbolic analysis (requires tamarin-prover >= 1.8 and maude).
formal:
	tamarin-prover --prove formal/dit.spthy +RTS -N4 -RTS
