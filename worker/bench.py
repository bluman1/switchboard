"""Relay benchmark. Usage: bench.py <label> <base_url> [senders] [publishes] [threads]
Same client code and operations against every target. Prints one JSON line of results."""
import json, os, sys, time, statistics, threading
sys.path.insert(0, "/Users/michael/WebstormProjects/switchboard/src")
import httpx
from switchboard import crypto, envelope, reqsig
from switchboard.canonical import canonical_bytes

label, URL = sys.argv[1], sys.argv[2]
N_SENDERS = int(sys.argv[3]) if len(sys.argv) > 3 else 60
N_PUB = int(sys.argv[4]) if len(sys.argv) > 4 else 300
THREADS = int(sys.argv[5]) if len(sys.argv) > 5 else 16
OPERATOR = os.environ.get("BENCH_OPERATOR")  # "<seed>:<xsec>" to vouch senders to T1 (needed where T0 limits bite)
RUN = os.urandom(3).hex()

c = httpx.Client(base_url=URL, timeout=60)
relay_pub = c.get("/v1/guide").json()["relay"]["pubkey"]
CARD = {"capabilities": [{"name": "web-research", "description": "x", "input_schema": {"question": "string"}, "output_schema": {"brief": "string"}}], "constraints": []}

def register(handle, kp):
    body = {"handle": handle, "ed25519_pubkey": kp.ed25519_pub, "x25519_pubkey": kp.x25519_pub, "runtime": "custom", "capability_card": CARD}
    body["signature"] = kp.sign(canonical_bytes(body))
    r = c.post("/v1/register", content=json.dumps(body)); assert r.status_code == 200, r.text

def med(xs): return statistics.median(xs) * 1e3
def p95(xs): return sorted(xs)[int(len(xs) * .95)] * 1e3

res = {"target": label, "url": URL, "senders": N_SENDERS, "publishes": N_PUB, "threads": THREADS}
senders = [(f"bench-{RUN}-{i}", crypto.Keypair.generate()) for i in range(N_SENDERS)]
lat = []
for h, k in senders:
    t0 = time.perf_counter(); register(h, k); lat.append(time.perf_counter() - t0)
res["register_ms_median"] = round(med(lat), 2)

if OPERATOR:  # vouch every sender to T1 so per-tier publish limits do not cap the run
    seed, xsec = OPERATOR.split(":"); op = crypto.Keypair(bytes.fromhex(seed), bytes.fromhex(xsec))
    op_handle = c.get(f"/v1/directory/{op.ed25519_pub}").json()["handle"]
    from datetime import datetime, timedelta, timezone
    exp = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for h, k in senders:
        env = envelope.sign(envelope.build(type="vouch", from_handle=op_handle, from_pubkey=op.ed25519_pub, to=relay_pub,
              payload={"subject_pubkey": k.ed25519_pub, "subject_handle": h, "statement": "bench", "expires_at": exp}), op)
        r = c.post("/v1/publish", content=json.dumps(env)); assert r.status_code == 200, r.text

recv_h, recv = senders[0]
def mk(i):
    h, k = senders[1 + i % (N_SENDERS - 1)]
    box = crypto.seal(recv.x25519_pub, canonical_bytes({"text": "hello " * 20}))
    return json.dumps(envelope.sign(envelope.build(type="dm", from_handle=h, from_pubkey=k.ed25519_pub, to=recv.ed25519_pub, payload=box), k))
envs = [mk(i) for i in range(N_PUB * 2)]

lat = []; t = time.perf_counter()
for e in envs[:N_PUB]:
    t0 = time.perf_counter(); r = c.post("/v1/publish", content=e); lat.append(time.perf_counter() - t0); assert r.status_code == 200, r.text
res["publish_ms_median"] = round(med(lat), 2); res["publish_ms_p95"] = round(p95(lat), 2); res["publish_rps_sequential"] = round(N_PUB / (time.perf_counter() - t))

# Concurrency from separate processes, so the load generator is not GIL-bound.
import multiprocessing as mp
def worker(chunk):
    cc = httpx.Client(base_url=URL, timeout=60)
    return [cc.post("/v1/publish", content=e).status_code for e in chunk]
rest = envs[N_PUB:]
t = time.perf_counter()
with mp.get_context("fork").Pool(THREADS) as pool:
    codes = [c_ for part in pool.map(worker, [rest[i::THREADS] for i in range(THREADS)]) for c_ in part]
res["publish_rps_concurrent"] = round(len(rest) / (time.perf_counter() - t)); res["concurrent_ok"] = f"{codes.count(200)}/{len(codes)}"

h = reqsig.sign_request(recv, relay_pub, "GET", "/v1/inbox", "cursor=0&limit=200", b"")
t0 = time.perf_counter(); r = c.get("/v1/inbox?cursor=0&limit=200", headers=h); res["inbox200_ms"] = round((time.perf_counter() - t0) * 1e3, 1); res["inbox200_kb"] = round(len(r.content) / 1024)
lat = []
for _ in range(100):
    t0 = time.perf_counter(); c.get(f"/v1/directory/{senders[min(7, N_SENDERS - 1)][0]}"); lat.append(time.perf_counter() - t0)
res["lookup_ms_median"] = round(med(lat), 2)
lat = []
for _ in range(30):
    t0 = time.perf_counter(); c.get("/v1/directory?offers=web-research&limit=50"); lat.append(time.perf_counter() - t0)
res["search_ms_median"] = round(med(lat), 2)
lat = []
for _ in range(100):
    t0 = time.perf_counter(); c.get("/v1/guide"); lat.append(time.perf_counter() - t0)
res["guide_ms_median"] = round(med(lat), 2)
lat = []
for _ in range(30):
    t0 = time.perf_counter(); c.get("/"); lat.append(time.perf_counter() - t0)
res["root_page_ms_median"] = round(med(lat), 2)
print(json.dumps(res))
