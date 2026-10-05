# Data

```
kelmarsh/                              real turbine SCADA data the simulator serves
  km_scada_sample_2022_excerpt.csv     20 real rows, committed
  km_scada_sample_2022.csv             full file, only after `make fetch-dataset` (gitignored)
raw/scenario_captures/*.jsonl          tap records captured during each live scenario run
clean/
  kelmarsh_power_clean.csv             typed + checked rows, plus the register value served
  kelmarsh_quality_report.json         row counts and check results
processed/
  scenario_alerts/*.json               every alert each scenario raised, as the engine emitted it
  scenario_alert_counts.csv            alerts per scenario, rule and severity
  setpoint_writes.csv                  each process-manipulation write and which rules fired on it
  segmentation_cases.csv               the 20 kernel-enforcement test cases
  prioritizer_examples.csv             the two worked examples in docs/results.md
  prioritizer_sweep.csv                operational risk across CVSS 0-10, four exposure profiles
```

## How each file is produced

| File | Produced by | Needs |
|---|---|---|
| `raw/scenario_captures/<scenario>.jsonl` | `make demo-<scenario>` (with `--write-results`, which the make targets pass) | the live lab (`make lab-up`) |
| `processed/scenario_alerts/<scenario>.json` | same run | same |
| `clean/*`, the other `processed/*` files | `python scripts/build_data.py` | only the files above |
| `docs/figures/*.png` | `python scripts/make_charts.py` | only `clean/` and `processed/` |

`build_data.py` replays the process-manipulation capture through a fresh
detection engine one record at a time and refuses to write anything if the
per-rule alert totals differ from the scenario's own run. That's how each
alert is tied to the write that caused it, since alerts carry no record id.

The network-segmentation scenario has no capture file: it tests kernel
enforcement with real TCP connects between network namespaces, not traffic
through the tap. Its per-case results are in `segmentation_cases.csv`.

## Capture record fields

One JSON object per connection the tap saw: `ts`, `uid`, `src_ip`,
`src_port`, `dst_ip`, `dst_port`, `service`, `zone`, `connected`,
`duration_s`, `orig_bytes`, `resp_bytes`, `backend_port`, and for Modbus
traffic `modbus_function_code` / `modbus_function_name`, plus
`modbus_write_register_addr` / `modbus_write_register_value` for writes.
The source addresses are the lab's simulated hosts (`127.0.0.x`, mapped
to zones in `lab/network_zones.json`), not real machines.

## Kelmarsh data

See `kelmarsh/README.md` for provenance and licence (CC-BY-4.0). Only 20
rows are committed because the environment this repo was built in can't
reach zenodo.org. To use the full file:

```bash
make fetch-dataset
python scripts/build_data.py && python scripts/make_charts.py
```

`build_data.py` picks up the full file automatically when it is present,
and `kelmarsh_quality_report.json` records which file was used
(`is_full_dataset`).
