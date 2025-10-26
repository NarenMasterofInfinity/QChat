# QChat (Verbose Logging, QUIC-compatible)

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run (TCP)
```bash
python -m qchat start-server --host 0.0.0.0 --port 8443
python -m qchat interactive --host 127.0.0.1 --port 8443
```

## Run (QUIC)
```bash
python -m qchat start-server --quic --host 0.0.0.0 --port 8443
python -m qchat interactive --quic --host 127.0.0.1 --port 8443
```

## Test
```bash
python test.py --host 127.0.0.1 --port 8443 --quic   --alice alice --alice-password alice   --bob bob --bob-password bob   --group birds --out results.csv
```

## Verbose logging
Set `QCHAT_DEBUG=1` for console logs and JSONL audit:
- Server: `~/.qchat/server/logs/events-YYYYMMDD.jsonl` (or `$QCHAT_HOME/server/logs/...`)
- Client/test: prints per-step with timestamps.

