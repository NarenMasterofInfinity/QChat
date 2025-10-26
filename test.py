# test.py
import asyncio, argparse, base64, os, time, pandas as pd
from qchat.conn import Conn
from qchat.transport.quic_transport import open_quic_connection, quic_shutdown
from qchat.crypto.hkdf import hkdf
from qchat.crypto.aead import AEAD, nonce_from

def ts():
    t = time.localtime()
    return time.strftime("%H:%M:%S", t) + f".{int((time.time()%1)*1000):03d}"

def log(m):
    print(f"[{ts()}] {m}", flush=True)

async def open_conn(host, port, quic, name):
    if quic:
        log(f"open {name} (QUIC)")
        return await open_quic_connection(host, port)
    log(f"open {name} (TCP)")
    return await asyncio.open_connection(host, port)

async def ensure_user(c: Conn, u: str, p: str, who: str):
    try:
        log(f"{who}: register")
        r = await c.request({
            'type':'register','user':u,'password':p,
            'sig_pk_b64':base64.b64encode(b'x').decode(),
            'kem_pk_b64':base64.b64encode(b'y').decode()
        }, timeout=8.0)
        log(f"{who}: register -> {r.get('type')}")
    except Exception as e:
        log(f"{who}: register err (ok if exists): {e}")

    log(f"{who}: login")
    r = await c.request({'type':'login','user':u,'password':p}, timeout=8.0)
    log(f"{who}: login -> {r.get('type')}")
    assert r.get('type')=='login_ok', f"login failed for {who}: {r}"

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8443)
    ap.add_argument('--quic', action='store_true')
    ap.add_argument('--measure-downlink', action='store_true',
                    help="also measure server->member broadcast time for the same message")
    ap.add_argument('--alice', default='alice')
    ap.add_argument('--alice-password', default='alice')
    ap.add_argument('--bob', default='bob')
    ap.add_argument('--bob-password', default='bob')
    ap.add_argument('--group', default='birds')
    ap.add_argument('--out', default='results.csv')
    args = ap.parse_args()

    # Open two connections
    r1,w1 = await open_conn(args.host,args.port,args.quic, "admin");  c1=Conn(r1,w1,"admin");  await c1.start_reader()
    r2,w2 = await open_conn(args.host,args.port,args.quic, "member"); c2=Conn(r2,w2,"member"); await c2.start_reader()

    # Users & group
    await ensure_user(c1, args.alice, args.alice_password, "alice")
    await ensure_user(c2, args.bob,   args.bob_password,   "bob")
    log("create_group"); log(await c1.request({'type':'create_group','group':args.group,'user':args.alice}))
    log("join_group");   log(await c2.request({'type':'join_group','group':args.group,'user':args.bob}))
    log("approve_member (may not reply immediately)")
    try:
        _ = await c1.request({'type':'approve_member','group':args.group,'user':args.alice,'member':args.bob}, timeout=1.5)
        log("approve_member -> ok")
    except Exception as e:
        log(f"approve_member -> pending ({e})")

    # Confirm approval
    log("poll approval")
    ok=False
    for i in range(25):
        g = await c1.request({'type':'list_groups'})
        m = g.get('groups',{}).get(args.group,{}).get('members',{}).get(args.bob,{}).get('approved', False)
        log(f"approval check {i}: {m}")
        if m: ok=True; break
        await asyncio.sleep(0.2)
    assert ok, "approval did not show up"

    # Reuse key & AEAD for micro-optimization
    key  = hkdf(f"{args.group}|{args.alice}".encode())
    aead = AEAD(key)

    rows=[]
    sizes = [16, 128, 1024, 4096, 16384]
    for sz in sizes:
        ad = f"{args.group}|{args.alice}|{sz}".encode()
        n  = nonce_from(key, sz, ad)
        pt = os.urandom(sz)
        ct = aead.enc(n, pt, ad)

        # Measure Alice->Server->Alice ACK RTT
        t0 = time.time()
        ack = await c1.request({
            'type':'chat','group':args.group,'user':args.alice,
            'cipher': ct, 'ad': ad
        }, timeout=5.0)
        t1 = time.time()
        rows.append({'suite':'e2e_rtt','size':sz,'value_ms':(t1 - t0)*1000.0})

        # Optionally measure Server->Bob broadcast time for same msg_id
        if args.measure_downlink:
            msg_id = ack.get('msg_id')
            t_send = time.time()
            while True:
                m = await asyncio.wait_for(c2.push_queue.get(), timeout=2.0)
                if m.get('type') == 'chat' and m.get('msg_id') == msg_id:
                    break
            t_recv = time.time()
            rows.append({'suite':'downlink','size':sz,'value_ms':(t_recv - t_send)*1000.0})

    # Save results
    df = pd.DataFrame(rows)
    df.to_csv(args.out, index=False)
    print(df)
    log(f"saved {args.out}")

    # Cleanup
    await c1.close(); await c2.close()
    if args.quic:
        await quic_shutdown()

if __name__=='__main__':
    asyncio.run(main())
