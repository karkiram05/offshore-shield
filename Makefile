.PHONY: install fetch-dataset lab-up lab-down demo-discovery demo-cicd demo-lateral-movement demo-process-manipulation demo-network-segmentation dashboard test lint clean

install:
	pip install -r requirements.txt

fetch-dataset:
	curl -L -o data/kelmarsh/km_scada_sample_2022.csv \
		"https://zenodo.org/records/15799719/files/km_scada_sample_2022.csv?download=1"
	@echo "Full Kelmarsh dataset downloaded. The simulator uses it automatically when present."

lab-up:
	mkdir -p logs
	python3 lab/plc_sim/turbine_modbus_server.py --port 5020 --interval 2 > logs/turbine.out 2>&1 &
	python3 lab/plc_sim/hvac_modbus_server.py --port 5021 --interval 2 > logs/hvac.out 2>&1 &
	python3 lab/services/mgmt_banner_service.py --port 5040 > logs/mgmt.out 2>&1 &
	sleep 1
	python3 lab/tap/network_tap.py --config lab/tap/taps.json --log logs/conn.log > logs/tap.out 2>&1 &
	sleep 1
	@echo "Lab is up. Turbine PLC on :6502, HVAC on :6521, jump-host mgmt on :6530, eng-workstation mgmt on :6531 (all via the tap)."
	@echo "Run 'make demo-discovery', 'make demo-lateral-movement', 'make demo-cicd', or 'make demo-process-manipulation' in another shell, or 'python3 detection/engine.py' to watch alerts live."

lab-down:
	-pkill -f "lab/plc_sim/turbine_modbus_server.py"
	-pkill -f "lab/plc_sim/hvac_modbus_server.py"
	-pkill -f "lab/services/mgmt_banner_service.py"
	-pkill -f "lab/tap/network_tap.py"
	@echo "Lab processes stopped."

demo-discovery:
	python3 scenarios/scenario_discovery.py --write-results

demo-cicd:
	python3 scenarios/scenario_cicd_identity.py --write-results

demo-lateral-movement:
	python3 scenarios/scenario_lateral_movement.py --write-results

demo-process-manipulation:
	python3 scenarios/scenario_process_manipulation.py --write-results

demo-network-segmentation:
	@echo "Requires root / CAP_NET_ADMIN (creates real Linux network namespaces) -- run with sudo if needed."
	python3 scenarios/scenario_network_segmentation.py --write-results

dashboard:
	python3 dashboard/generate_dashboard.py
	@echo "Wrote dashboard/index.html -- open it in a browser."

test:
	python3 -m pytest tests/ -v

lint:
	pip install --quiet bandit pip-audit
	bandit -r detection vuln lab scenarios dashboard -q
	# pip-audit can't look up advisories for trustgraph (a first-party git
	# dependency, not on PyPI) -- audit the PyPI-published subset of
	# requirements.txt instead of a hand-maintained duplicate list, so
	# this can't silently drift when requirements.txt changes. See
	# .github/workflows/ci.yml's pip-audit step for the same filter.
	grep -v '^trustgraph' requirements.txt | grep -v '@ git+' > /tmp/offshoreshield-pypi-requirements.txt
	pip-audit -r /tmp/offshoreshield-pypi-requirements.txt

clean:
	rm -f logs/*.log logs/*.out
	rm -rf __pycache__ */__pycache__ .pytest_cache
