.PHONY: all build test train compare bench clean format install-deps fix-perms verify

PYTHON ?= ./ml_env/bin/python
PIP ?= ./ml_env/bin/pip
TRAIN_DATA ?= ml/data/test_flows.csv
RANDOM ?= false

# Default target: Run everything including performance comparison
all: build test train compare bench
	@$(MAKE) fix-perms

# Comprehensive verification from a clean state
verify: clean build all

install-deps:
	@echo "Installing python dependencies..."
	$(PIP) install -r ml/requirements.txt
	$(PIP) install black flake8 rich

build:
	@echo "Compiling eBPF objects..."
	clang -O2 -g -target bpf -c src/tc_flow_full.bpf.c -o src/tc_flow_full.bpf.o -I src/
	clang -O2 -g -target bpf -c src/tc_flow.bpf.c -o src/tc_flow.bpf.o -I src/
	clang -O2 -g -target bpf -c src/tc_count.bpf.c -o src/tc_count.bpf.o -I src/
	clang -O2 -g -target bpf -c src/tc_icmp_rtt.bpf.c -o src/tc_icmp_rtt.bpf.o -I src/
	@echo "Build successful."

shield-test: build
	@echo "Running Adaptive ML Shield end-to-end test..."
	sudo bash scripts/test_shield.sh

shield-run: build
	@echo "Attaching BPF to loopback interface..."
	sudo tc qdisc del dev lo clsact 2>/dev/null || true
	sudo tc qdisc add dev lo clsact
	sudo tc filter add dev lo ingress bpf direct-action obj src/tc_flow_full.bpf.o sec tc
	@echo "Starting ML Shield Daemon in foreground..."
	sudo $(PYTHON) src/ml_shield_daemon.py

fix-perms:
	@echo "Fixing file permissions..."
	@if [ -n "$$SUDO_USER" ]; then \
		chown -R $$SUDO_USER:$$SUDO_USER . ; \
	elif [ "$$(id -u)" = "0" ]; then \
		chown -R $$(logname):$$(logname) . 2>/dev/null || true; \
	fi

test:
	@echo "Running all traffic capture tests..."
	sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/test_flows.csv $(RANDOM)
	@$(MAKE) fix-perms

train:
	@echo "Training ML models on $(TRAIN_DATA)..."
	$(PYTHON) ml/train.py --input $(TRAIN_DATA)

compare:
	@echo "Comparing Kernel vs User-space (ML) classifiers..."
	$(PYTHON) ml/compare_classifiers.py --input $(TRAIN_DATA)
	@echo "Generating Shield Impact visualization..."
	$(PYTHON) ml/plot_shield_impact.py

bench:
	@echo "Running RTT benchmark..."
	sudo bash scripts/bench/compare_rtt.sh lo 127.0.0.1 20 runs/rtt_compare.csv ml/results/rtt_compare.png
	@$(MAKE) fix-perms

format:
	@echo "Formatting Python files..."
	$(PYTHON) -m black ml/ src/
	@echo "Formatting C files..."
	find src -name "*.c" -exec clang-format -i {} +

lint:
	@echo "Linting Python files..."
	$(PYTHON) -m flake8 ml/ src/ --max-line-length=100 --ignore=E402,E501,E226,W503

clean:
	@echo "Cleaning compiled objects and temporary files..."
	find src -name "*.o" -delete
	rm -f ml/data/test_flows.csv
	rm -rf runs/
	rm -rf ml/results/
