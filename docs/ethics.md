# Ethics and scope boundaries

- **Nothing in this repo touches, scans, or references any real
  organization's infrastructure.** Every host, IP address, and Modbus
  register in `lab/` is fictional and self-contained; the only real data
  used is the public, CC-BY-4.0-licensed Kelmarsh Wind Farm SCADA dataset
  (see `data/kelmarsh/README.md`), which is production telemetry, not a
  network or system to attack.
- **The "scanner" is a scanner, not an exploit framework.** `lab/scanner/ot_scanner.py`
  opens TCP connections and reports what answered -- the same thing `nc -z`
  or a basic port sweep does. It has no exploitation, payload-delivery, or
  persistence capability, by design, and nothing in the roadmap (STATUS.md)
  adds any.
- **No component is built to run against anything outside this repo's own
  lab.** Every scenario script hardcodes `127.0.0.1` and this lab's own
  loopback-simulated hosts as its target.
- **Any company references are inspiration, not affiliation.** See
  `docs/orsted-case-study.md`'s disclaimer -- this project is not
  affiliated with, endorsed by, or built in cooperation with any named
  company. It's built from published, public information about the kinds
  of security problems that class of company describes needing solved.
- **No fabricated results.** Every number in `docs/results.md` and
  `scenarios/results/*.json` comes from actually running the code in this
  repo. If a scenario isn't built yet, STATUS.md says so instead of the
  README implying it exists.
