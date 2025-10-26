import os, sys, time, json
DEBUG = bool(int(os.environ.get("QCHAT_DEBUG","1")))
def ts_ms(): return int(time.time()*1000)
def ts_str():
    t=time.localtime(); return time.strftime("%H:%M:%S", t)+f".{int((time.time()%1)*1000):03d}"
def log(*a, **k):
    if DEBUG:
        print(f"[{ts_str()}]", *a, **k, flush=True)
def jline(path:str, obj:dict):
    try:
        with open(path,"a",encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False)+"\n")
    except Exception as e:
        if DEBUG: print("[log] jsonl write failed:", e, file=sys.stderr)

