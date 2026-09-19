.PHONY: install fetch-dataset lab-up lab-down demo-discovery demo-cicd test lint clean

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
	sleep 1
	python3 lab/tap/network_tap.py --config lab/tap/taps.json --log logs/conn.log > logs/tap.out 2>&1 &
	sleep 1
	@echo "Lab is up. Turbine PLC on :6502 (via tap), HVAC on :6521 (via tap)."
	@echo "Run 'make demo-discovery' in another shell, or 'python3 detection/engine.py' to watch alerts live."

lab-down:
	-pkill -f "lab/plc_sim/turbine_modbus_server.py"
	-pkill -f "lab/plc_sim/hvac_modbus_server.py"
	-pkill -f "lab/tap/network_tap.py"
	@echo "Lab processes stopped."

demo-discovery:
	python3 scenarios/scenario_discovery.py --write-results

demo-cicd:
	python3 scenarios/scenario_cicd_identity.py --write-results

test:
	python3 -m pytest tests/ -v

lint:
	pip install --quiet bandit pip-audit
	bandit -r detection vuln lab scenarios -q
	pip-audit -r requirements.txt

clean:
	rm -f logs/*.log logs/*.out
	rm -rf __pycache__ */__pycache__ .pytest_cache
