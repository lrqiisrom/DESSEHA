import hmac
import random
import math
from Crypto.Cipher import AES
import time
import gmpy2
from gmpy2 import mpz
import json
import os
import re
import csv
import sys

from crypto_primitives import (
    ensure_bytes,
    prf_md5,
    prf_to_int_mod_q,
    invert_mod_q,
    group_exp,
)

# Constants consistent with main.py
random_length = 128
g1 = mpz(2141434891434191460597654106285009794456474073127443963580690795002163321265105245635441519012876162226508712450114295048769820153232319693432987768769296824615642594321423205772115298200265241761445943720948512138315849294187201773718640619332629679913150151901308086084524597187791163240081868198195818488147354220506153752944012718951076418307414874651394412052849270568833194858516693284043743223341262442918629683831581139666162694560502910458729378169695954926627903314499763149304778624042360661276996520665523643147485282255746183568795735922844808611657078638768875848574571957417538833410931039120067791054495394347033677995566734192953459076978334017849678648355479176605169830149977904762004245805443987117373895433551186090322663122981978369728727863969397652199851244115246624405814648225543311628517631088342627783146899971864519981709070067428217313779897722021674599747260345113463261690421765416396528871227)
p = mpz(3268470001596555685058361448517594259852327289373621024658735136696086397532371469771539343923030165357102680953673099920140531685895962914337283929936606946054169620100988870978124749211273448893822273457310556591818639255714375162549119727203843057453108725240320611822327564102565670538516259921126103868685909602654213513456013263604608261355992328266121535954955860230896921190144484094504405550995009524584190435021785232142953886543340776477964177437292693777245368918022174701350793004000567940200059239843923046609830997768443610635397652600287237380936753914127667182396037677536643969081476599565572030244212618673244188481261912792928641006121759661066004079860474019965998840960514950091456436975501582488835454404626979061889799215263467208398224888341946121760934377719355124007835365528307011851448463147156027381826788422151698720245080057213877012399103133913857496236799905578345362183817511242131464964979)
q = mpz(93911948940456861795388745207400704369329482570245279608597521715921884786973)

DATASET_LIMIT = 2000


# ----------------------
# Entity definitions
# ----------------------
class DataOwner:
    def __init__(self):
        # Keys for PRF Fp
        self.KZ = None
        self.KY = None
        self.KX = None
        # Keys for PRF F (HMAC-MD5)
        self.KS = None
        self.KA = None  # address key
        # TSet tag key
        self.KT = None

    def setup(self, delta_seconds: int, time0: int):
        # Select client keys
        self.KZ = random_string(random_length)
        self.KY = random_string(random_length)
        self.KX = random_string(random_length)
        self.KS = random_string(random_length)
        self.KA = random_string(random_length)
        self.KT = random_string(random_length)
        # Initialize time server with kTS
        ts = TimeServer(delta_seconds, time0)
        return (self.KS, self.KX, self.KY, self.KZ, self.KA, self.KT), ts


class User:
    def __init__(self, uid: str):
        self.uid = uid


class CloudServer:
    def __init__(self):
        # TSet: stag -> list of (e, addr)
        self.TSet = {}
        # XSet: set of group elements (xtags)
        self.XSet = set()
        # TimeSet: addr -> (time_j, G_list)
        self.TimeSet = {}

    # Helper used in Algorithm 2: return t (list for stag)
    def tset_retrieve(self, stag):
        return self.TSet.get(stag, [])


class TimeServer:
    def __init__(self, delta_seconds: int, time0: int):
        self.delta = delta_seconds
        self.time0 = time0
        self.kTS = random_string(random_length)

    # Fp(kTS, t) -> time token in Z_q
    def time_token(self, t: int):
        return prf_to_int_mod_q(self.kTS, str(t), q)

    # current time point and its token, and former token
    def current_time_and_tokens(self, now: int):
        x_j = self.time_token(now)
        x_prev = self.time_token(now - self.delta)
        return now, x_j, x_prev



def load_dataset_from_fs(root_dir, default_duration_steps=1):
    root = os.path.abspath(root_dir)
    json_path = os.path.join(root, "dataset.json")
    csv_path = os.path.join(root, "dataset.csv")
    manifest_path = os.path.join(root, "manifest.jsonl")
    if os.path.isfile(json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = []
        for item in data:
            if len(out) >= DATASET_LIMIT:
                break
            fid = item.get("file_id") or item.get("id") or item.get("fid")
            kws = item.get("keywords") or []
            d = item.get("duration_steps") or item.get("d") or default_duration_steps
            out.append((str(fid), list(map(str, kws)), int(d)))
        return out
    if os.path.isfile(csv_path):
        out = []
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if len(out) >= DATASET_LIMIT:
                    break
                fid = row.get("file_id") or row.get("id") or row.get("fid")
                kw_str = row.get("keywords") or ""
                kws = [k.strip() for k in kw_str.split(",") if k.strip()]
                d_raw = row.get("duration_steps") or row.get("d")
                d = int(d_raw) if d_raw is not None and str(d_raw).strip() != "" else default_duration_steps
                out.append((str(fid), list(map(str, kws)), int(d)))
        return out
    if os.path.isfile(manifest_path):
        out = []
        with open(manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                if len(out) >= DATASET_LIMIT:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                file_field = item.get("file") or item.get("path") or item.get("file_id") or item.get("id")
                fid_base = os.path.basename(str(file_field)) if file_field else "file"
                fid = os.path.splitext(fid_base)[0]
                kws = item.get("keywords") or []
                d = item.get("duration_steps") or item.get("d") or default_duration_steps
                out.append((str(fid), list(map(str, kws)), int(d)))
        return out
    out = []
    for dirpath, _, filenames in os.walk(root):
        if len(out) >= DATASET_LIMIT:
            break
        for fn in filenames:
            if len(out) >= DATASET_LIMIT:
                break
            if fn.lower().endswith(".txt"):
                fpath = os.path.join(dirpath, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except Exception:
                    text = ""
                tokens = re.findall(r"[A-Za-z0-9_]+", text.lower())
                kws = list(dict.fromkeys(tokens))
                fid = os.path.splitext(os.path.relpath(fpath, root))[0]
                out.append((fid, kws, int(default_duration_steps)))
    return out

# ----------------------
# Algorithm 1: Constructing EDB
# ----------------------
def construct_edb(do: DataOwner, server: CloudServer, ts: TimeServer, DB, delta_seconds: int):
    KS, KX, KY, KZ, KA, KT = do.KS, do.KX, do.KY, do.KZ, do.KA, do.KT
    # T: map w1 -> list of (e, addr) tuples, later packed into TSet via tag
    T = {}
    XSet = set()
    TimeSet = {}

    # Collect global vocabulary
    W_all = set()
    for (fid, kws, d_steps) in DB:
        for w in kws:
            W_all.add(w)

    # For each keyword w, iterate documents containing w
    for w in W_all:
        Ke = prf_md5(KS, w)  # symmetric key for id encryption (AES-ECB)
        c = 1
        t_list = []
        # Random order of docs that contain w
        docs_with_w = [(fid, d_steps) for (fid, kws, d_steps) in DB if w in kws]
        random.shuffle(docs_with_w)
        for (fid, d_steps) in docs_with_w:
            # e = Sym.Enc(Ke, id)
            aes = AES.new(key=Ke, mode=AES.MODE_ECB)
            e = aes.encrypt(fid.zfill(16).encode('utf-8'))

            # z = Fp(KZ, w||c)
            z = prf_to_int_mod_q(KZ, w + "||" + str(c), q)
            # y_id = Fp(KY, id)
            y_id = prf_to_int_mod_q(KY, fid, q)

            # xtag = g^{Fp(KX,w) * Fp(KY,id)} 
            alpha = prf_to_int_mod_q(KX, w, q)
            exp = (alpha * y_id) % q
            xtag = group_exp(g1, exp, p)

            # addr = F(KA, w||c)
            addr = prf_md5(KA, w + "||" + str(c))

            t_list.append((e, addr))
            XSet.add(xtag)
            # Store for time server processing: b = Fp(KY,id) * z^{-1}
            b = (y_id * invert_mod_q(z, q)) % q
            TimeSet[addr] = (b, d_steps)
            c += 1

        # Tag for w1 (we use KT as tag key)
        stag = prf_md5(KT, w)
        T[stag] = t_list

    # Time Server processing: replace (b, d) with (time_j, G)
    processed_TimeSet = {}
    # Determine a reference current time (use ts.time0 for EDB build)
    current_time = ts.time0
    for addr, (b, d_steps) in TimeSet.items():
        # s = ceil(d/δ) where d = d_steps * δ
        s = d_steps
        # choose time tokens x_{j-1}, x_j, ..., x_{j+s}
        x_tokens = [ts.time_token(current_time + k * ts.delta) for k in range(-1, s + 1)]
        # Select polynomial y = a x + b over Z_q, with b as provided
        a = mpz(random.randrange(1, int(q))) % q
        # Compute y_i values for indices i in [j-1, j+s]
        y_vals = []
        for x_i in x_tokens:
            y_vals.append((a * x_i + b) % q)
        # Compute g_i = y_i x_{i-1} − y_{i-1} x_i for i in [j, j+s]
        G_list = []
        for i in range(1, len(x_tokens)):
            y_i = y_vals[i]
            y_prev = y_vals[i - 1]
            x_i = x_tokens[i]
            x_prev = x_tokens[i - 1]
            g_i = (y_i * x_prev - y_prev * x_i) % q
            G_list.append(g_i)
        processed_TimeSet[addr] = (current_time, G_list)

    # Load into cloud server
    server.TSet = T
    server.XSet = XSet
    server.TimeSet = processed_TimeSet
    # Return EDB pieces (for clarity)
    return server


# ----------------------
# Algorithm 2: TokenGen (with h_c corrigendum)
# ----------------------
def tokengen(do: DataOwner, server: CloudServer, ts: TimeServer, query_keywords, delta_seconds: int):
    # Client side
    xToken = {}
    # stag for w1
    w1 = query_keywords[0]
    stag = prf_md5(do.KT, w1)
    # Retrieve t from cloud
    t_list = server.tset_retrieve(stag)
    t_len = len(t_list)
    # Build base tokens for j >= 2
    for c in range(1, t_len + 1):
        for j in range(2, len(query_keywords) + 1):
            wj = query_keywords[j - 1]
            base = (prf_to_int_mod_q(do.KX, wj, q) * prf_to_int_mod_q(do.KZ, w1 + "||" + str(c), q)) % q
            xToken[(c, j)] = group_exp(g1, base, p)

    # Send xToken to time server and get time', tokens
    now = ts.time0 + ts.delta  # simulate a query at next interval
    time_prime, x_j, x_prev = ts.current_time_and_tokens(now)

    # Time Server side (corrigendum):
    hc = {}
    for c in range(1, t_len + 1):
        r_jc = prf_to_int_mod_q(ts.kTS, str(time_prime) + "||" + str(c), q)
        # h_c = r_{j,c}^{-1} * (x_{j-1} − x_j) mod q  [勘误]
        hc[c] = (invert_mod_q(r_jc, q) * ((x_prev - x_j) % q)) % q
        # Forward xToken to cloud; to make matching correct, neutralize r by applying r^{-1}
        # 说明：为与 xtag 指数 b 对齐，这里用 r^{-1}，否则会出现额外的 r 因子。
        for j in range(2, len(query_keywords) + 1):
            xToken[(c, j)] = group_exp(xToken[(c, j)], invert_mod_q(r_jc, q), p)

    # Return to client (who forwards to cloud)
    return stag, t_len, xToken, time_prime, hc


# ----------------------
# Algorithm 3: Search on cloud, decrypt on client
# ----------------------
def search(do: DataOwner, server: CloudServer, ts: TimeServer, query_keywords, stag, t_len, xToken, time_prime, hc):
    Res = []
    w1 = query_keywords[0]
    Ke = prf_md5(do.KS, w1)
    # For each c, fetch tuple and corresponding time info
    for c in range(1, t_len + 1):
        e, addr = server.tset_retrieve(stag)[c - 1]
        # (time, G)
        time_j, G_list = server.TimeSet[addr]
        # ŝ = (time' − time)/δ  -> index into G
        s_hat = math.ceil((time_prime - time_j) / ts.delta)
        if s_hat < 0 or s_hat >= len(G_list):
            continue
        # b' = G[ŝ] / h_c  (i.e., G[ŝ] * h_c^{-1} mod q)
        b_prime = (G_list[s_hat] * invert_mod_q(hc[c], q)) % q
        # Check membership across all j
        ok = True
        max_range = len(query_keywords) - 1
        random_number = random.randint(1, max_range) if max_range >= 1 else 1
        for j in range(2, len(query_keywords) + 1):
            candidate = group_exp(xToken[(c, j)], b_prime, p)
            random_number -= 1
            if candidate not in server.XSet:
                ok = False
                if random_number == 0:
                    break
        if ok:
            aes = AES.new(key=Ke, mode=AES.MODE_ECB)
            fid_plain = aes.decrypt(e).decode('utf-8')
            Res.append(fid_plain)
    # Deduplicate
    return list(dict.fromkeys(Res))


# ----------------------
# Demo helper
# ----------------------
def random_string(random_string_length):
    seed = "01"
    sa = []
    for i in range(random_string_length):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return hex(int(salt, 2))


# ----------------------
# Correctness helpers and tests
# ----------------------

def tokengen_at(do: DataOwner, server: CloudServer, ts: TimeServer, query_keywords, now: int):
    xToken = {}
    w1 = query_keywords[0]
    stag = prf_md5(do.KT, w1)
    t_list = server.tset_retrieve(stag)
    t_len = len(t_list)
    for c in range(1, t_len + 1):
        for j in range(2, len(query_keywords) + 1):
            wj = query_keywords[j - 1]
            base = (prf_to_int_mod_q(do.KX, wj, q) * prf_to_int_mod_q(do.KZ, w1 + "||" + str(c), q)) % q
            xToken[(c, j)] = group_exp(g1, base, p)
    time_prime, x_j, x_prev = ts.current_time_and_tokens(now)
    hc = {}
    for c in range(1, t_len + 1):
        r_jc = prf_to_int_mod_q(ts.kTS, str(time_prime) + "||" + str(c), q)
        hc[c] = (invert_mod_q(r_jc, q) * ((x_prev - x_j) % q)) % q
        for j in range(2, len(query_keywords) + 1):
            xToken[(c, j)] = group_exp(xToken[(c, j)], invert_mod_q(r_jc, q), p)
    return stag, t_len, xToken, time_prime, hc


def test_correctness_small():
    random.seed(1)
    do = DataOwner()
    delta = 60
    time0 = 1700000000
    _, ts = do.setup(delta, time0)
    server = CloudServer()
    DB = [
        ("doc_A", ["apple", "banana"], 2),
        ("doc_B", ["apple", "cherry"], 1),
        ("doc_C", ["banana", "cherry"], 3),
    ]
    construct_edb(do, server, ts, DB, delta)
    qkws = ["apple"]
    stag, t_len, xToken, time_prime, hc = tokengen_at(do, server, ts, qkws, time0 + delta)
    res = search(do, server, ts, qkws, stag, t_len, xToken, time_prime, hc)
    print("test_correctness_small | search raw:", res)
    res_norm = {r.lstrip('0') for r in res}
    print("test_correctness_small | search normalized:", sorted(res_norm))
    late_time = time0 + 1 * delta + 1
    # 使用 tokengen_at 在指定时间点生成令牌；tokengen 固定使用 time0+delta
    stag, t_len, xToken, time_prime, hc = tokengen_at(do, server, ts, qkws, late_time)
    res2 = search(do, server, ts, qkws, stag, t_len, xToken, time_prime, hc)
    print("test_correctness_small | late-time search raw:", res2)


def test_membership_derivation():
    random.seed(2)
    do = DataOwner()
    delta = 60
    time0 = 1700000000
    _, ts = do.setup(delta, time0)
    server = CloudServer()
    DB = [
        ("doc_A", ["apple", "banana"], 2),
        ("doc_B", ["apple", "cherry"], 1),
    ]
    construct_edb(do, server, ts, DB, delta)
    qkws = ["apple", "banana"]
    stag, t_len, xToken, time_prime, hc = tokengen_at(do, server, ts, qkws, time0 + delta)
    (e, addr) = server.tset_retrieve(stag)[0]
    time_j, G_list = server.TimeSet[addr]
    s_hat = (time_prime - time_j) // ts.delta
    b_prime = (G_list[s_hat] * invert_mod_q(hc[1], q)) % q
    Ke = prf_md5(do.KS, qkws[0])
    fid_padded = AES.new(key=Ke, mode=AES.MODE_ECB).decrypt(e).decode('utf-8')
    fid = fid_padded.lstrip('0')
    y_id = prf_to_int_mod_q(do.KY, fid, q)
    alpha_2 = prf_to_int_mod_q(do.KX, qkws[1], q)
    expected = group_exp(g1, (alpha_2 * y_id) % q, p)
    candidate = group_exp(xToken[(1, 2)], b_prime, p)
    print("test_membership_derivation | expected == candidate:", expected == candidate)
    # assert candidate == expected


if __name__ == "__main__":
    # Example usage: build EDB and run a query
    # Also includes benchmarking helpers to measure construct_edb / tokengen / search

    def _time_call(fn, *args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return result, elapsed_ms

    def benchmark_once(max_duration_steps: int, delta_seconds: int, time0: int, query_keywords=None):
        # Setup entities
        do = DataOwner()
        _, ts = do.setup(delta_seconds, time0)
        server = CloudServer()
        dataset_dir = os.environ.get("DATASET_DIR") or os.path.join(os.getcwd(), "DATASET1_1")
        DB = load_dataset_from_fs(dataset_dir, default_duration_steps=max_duration_steps)
        # Measure construct_edb
        (_, edb_ms) = _time_call(construct_edb, do, server, ts, DB, delta_seconds)
        # Prepare query keywords
        if query_keywords is None:
            vocab = []
            seen = set()
            for (_, kws, _) in DB:
                for w in kws:
                    if w not in seen:
                        seen.add(w)
                        vocab.append(w)
            kcnt = min(3, max(1, len(vocab)))
            query_keywords = vocab[:kcnt]
            if len(query_keywords) < 2 and len(vocab) >= 1:
                query_keywords = query_keywords + vocab[:1]
        # Measure tokengen
        ((stag, t_len, xToken, time_prime, hc), tokengen_ms) = _time_call(
            tokengen, do, server, ts, query_keywords, delta_seconds
        )
        # Measure search
        (results, search_ms) = _time_call(
            search, do, server, ts, query_keywords, stag, t_len, xToken, time_prime, hc
        )
        return {
            "max_duration_steps": max_duration_steps,
            "delta_seconds": delta_seconds,
            "construct_edb_ms": edb_ms,
            "tokengen_ms": tokengen_ms,
            "search_ms": search_ms,
            "results_count": len(results),
        }

    qenv = os.environ.get("QUERY_KWS", "").strip()
    qcli = [s for s in sys.argv[1:] if s]
    if qenv:
        qkws = [s for s in re.split(r"[,\s]+", qenv) if s]
    elif qcli:
        qkws = qcli
    else:
        qkws = None

    def benchmark_suite(configs, runs: int = 3):
        summary = []
        for cfg in configs:
            agg = {"construct_edb_ms": 0.0, "tokengen_ms": 0.0, "search_ms": 0.0, "results_count": 0.0}
            last_detail = None
            for _ in range(runs):
                detail = benchmark_once(**cfg)
                last_detail = detail
                agg["construct_edb_ms"] += detail["construct_edb_ms"]
                agg["tokengen_ms"] += detail["tokengen_ms"]
                agg["search_ms"] += detail["search_ms"]
                agg["results_count"] += detail["results_count"]
            avg = {k: v / runs for k, v in agg.items()}
            summary.append({**cfg, **avg, "runs": runs})
        # Pretty print
        print("Benchmark results (averages over runs):")
        for item in summary:
            print(
                f"d_max={item['max_duration_steps']}, delta={item['delta_seconds']}s | "
                f"EDB={item['construct_edb_ms']:.2f}ms, TOK={item['tokengen_ms']:.2f}ms, "
                f"SEARCH={item['search_ms']:.2f}ms, MATCHES={int(item['results_count'])} (runs={item['runs']})"
            )

    delta = int(os.environ.get("DELTA_SECONDS", "60"))
    time0 = int(os.environ.get("TIME0", str(int(time.time()))))
    print("\n--- Benchmark suite ---")
    configs = [
        {"max_duration_steps": int(os.environ.get("DURATION_STEPS", "3")), "delta_seconds": delta, "time0": time0, "query_keywords": qkws},
    ]
    benchmark_suite(configs, runs=1)

    # Run correctness tests
    # print("\n--- Running correctness tests ---")
    # test_correctness_small()
    # test_membership_derivation()
    # print("Correctness tests passed.")
