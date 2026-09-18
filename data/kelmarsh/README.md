# Kelmarsh wind farm SCADA data

`km_scada_sample_2022_excerpt.csv` is 20 real rows (2022-01-01 00:00 through
03:10, 10-minute intervals: mean/std/min/max power in kW) taken directly from
the public Kelmarsh Wind Farm dataset:

- Source: Kelmarsh Power Data 2022 (IFAC RR Tutorial), Zenodo record
  [15799719](https://zenodo.org/records/15799719)
- License: CC-BY-4.0
- Full file: `km_scada_sample_2022.csv`, 4.8 MB, ~1,400 rows spanning
  several days of real turbine output at Kelmarsh Wind Farm, UK

## Why only 20 rows are committed here

This repo is built and tested inside a sandboxed environment whose network
egress is allowlisted to a small set of hosts (PyPI, npm, GitHub) and does
not include `zenodo.org`. The 20 rows above were pulled through a
text-extraction fetch that only returns a partial preview of the file, not
the full 4.8 MB download -- that's a constraint of the build environment,
not of the dataset or the license.

If you're running this on a normal machine or in GitHub Codespaces (which
has unrestricted internet), get the real, complete file with:

```bash
make fetch-dataset
```

which runs:

```bash
curl -L -o data/kelmarsh/km_scada_sample_2022.csv \
  "https://zenodo.org/records/15799719/files/km_scada_sample_2022.csv?download=1"
```

The simulator (`lab/plc_sim/turbine_modbus_server.py`) prefers the full file
when present and falls back to the 20-row excerpt otherwise, looping it to
produce a continuous telemetry stream. Either way, every value it serves
traces back to real measured turbine output, not synthetic data -- the only
difference is how many distinct real rows you're cycling through.

## What the columns mean

| Column | Meaning |
|---|---|
| `timestamp` | Start of the 10-minute aggregation window |
| `power_kw` | Mean active power output over the window |
| `power_std_kw` | Standard deviation of power within the window |
| `power_min_kw` / `power_max_kw` | Min/max instantaneous power within the window |

The full public dataset also includes per-turbine SCADA channels (rotor
speed, nacelle temperature, wind speed, pitch angle) across six Senvion
MM92 turbines and other Zenodo records under the same Kelmarsh project. This
excerpt uses the aggregate power-only file because it's the smallest
complete file in the collection and sufficient to drive a realistic
single-turbine Modbus register stream.
