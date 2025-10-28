# Retry: corrected DSSEHA prototype using P-256 curve and AES-GCM (simplified, educational)
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
import secrets

# Curve and order (secp256r1)
curve = ec.SECP256R1()
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def prf_scalar(key: bytes, data: bytes) -> int:
    out = hmac_sha256(key, data)
    return int.from_bytes(out, "big") % n

def derive_symkey(key: bytes, info: bytes) -> bytes:
    return hmac_sha256(key, info)  # 32 bytes

def scalar_point_bytes(scalar: int) -> bytes:
    s = scalar % n
    if s == 0:
        s = 1
    priv = ec.derive_private_key(s, curve)
    pub = priv.public_key()
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

class Server:
    def __init__(self):
        self.XSet = {}   # point_bytes -> ciphertext (nonce + ct_tag)
        self.USet = {}   # uid_hex -> U scalar
        self.ASet = {}   # aid_hex -> (alpha scalar, set(children))

    def add_X(self, Xb, Yb):
        if Xb in self.XSet:
            raise ValueError("Duplicate X (paper assumes uniqueness)")
        self.XSet[Xb] = Yb

    def add_U(self, uid_hex, U):
        self.USet[uid_hex] = U

    def add_A(self, aid_hex, alpha, parent_aid=None):
        if aid_hex not in self.ASet:
            self.ASet[aid_hex] = (alpha, set())
        if parent_aid is not None:
            if parent_aid not in self.ASet:
                self.ASet[parent_aid] = (1, set())
            a_alpha, children = self.ASet[parent_aid]
            children.add(aid_hex)
            self.ASet[parent_aid] = (a_alpha, children)

class DataOwner:
    def __init__(self):
        self.K1 = secrets.token_bytes(32)
        self.K2 = secrets.token_bytes(32)
        self.K3 = secrets.token_bytes(32)
        self.doc_keys = {}  # d -> (Kd scalar, Kd_tilde scalar, Kd_enc bytes)

    def setup(self):
        return (self.K1, self.K2, self.K3), Server()

    def add_docs(self, DOC, SK, server):
        K1,K2,K3 = SK
        for d, kws in DOC:
            Kd = prf_scalar(K1, d.encode())
            Kd_tilde = prf_scalar(K2, d.encode())
            Kd_enc = derive_symkey(K3, d.encode())
            self.doc_keys[d] = (Kd, Kd_tilde, Kd_enc)
            for w in kws:
                a = Kd_tilde
                b = prf_scalar(str(Kd).encode(), w.encode())
                #b = prf_scalar(Kd.to_bytes(32, "big"), w.encode())
                scalar_ab = (a * b) % n
                Xb = scalar_point_bytes(scalar_ab)
                nonce = secrets.token_bytes(12)
                Yb = nonce + AESGCM(Kd_enc).encrypt(nonce, d.encode(), None)
                server.add_X(Xb, Yb) #notice

class User:
    def __init__(self, uid):
        self.uid = uid.encode()
        self.Ku = secrets.token_bytes(32)
        self.Kutilde = secrets.token_bytes(32)
        self.UsrAuth = {}  # d -> None or (uid_hex, offtok_scalar)
        self.DocKey = {}   # d -> (Kd scalar, Kd_enc bytes)
        self.aid = None

    def enroll(self):
        return (self.Ku, self.Kutilde), {'UsrAuth': self.UsrAuth, 'DocKey': self.DocKey, 'aid': self.aid}

def OnlineAuth_DO_to_user(do, server, SK, user, IND):
    K1,K2,K3 = SK
    for d in IND:
        Kd, Kd_tilde, Kd_enc = do.doc_keys[d]
        uid = hmac_sha256(user.Kutilde, d.encode()).hex()
        val1 = Kd_tilde #notice
        val2 = prf_scalar(user.Ku, d.encode())
        inv_val2 = pow(val2, -1, n)
        U = (val1 * inv_val2) % n
        server.add_U(uid, U)
        user.DocKey[d] = (Kd, Kd_enc)
        user.UsrAuth[d] = None  # sDU

def OfflineAuth_A_to_B(server, A, B, IND):
    # ① 用户级别计算（放循环外）
    aid = hmac_sha256(A.Kutilde, B.uid).hex()
    alpha = prf_scalar(A.Ku, B.uid)
    if alpha == 0:
        alpha = 1
    alpha_inv = pow(alpha, -1, n)
    # ② 根据 A 的类型更新 ASet
    parent_aid = A.aid if A.aid else None
    server.add_A(aid, alpha_inv, parent_aid=parent_aid)

    # ③ 对每个文档生成 offtok
    for d in IND:
        if A.UsrAuth.get(d) is None:
            # A 是 sDU
            termA_d = prf_scalar(A.Ku, d.encode())
            termA_uB = prf_scalar(A.Ku, B.uid)
            s_off = (termA_d * termA_uB) % n
        else:
            uid_parent, s_parent = A.UsrAuth[d]
            termA_uB = prf_scalar(A.Ku, B.uid)
            s_off = (s_parent * termA_uB) % n #notice

        uid_parent = (
            hmac_sha256(A.Kutilde, d.encode()).hex()
            if A.UsrAuth.get(d) is None
            else A.UsrAuth[d][0]
        )

        B.UsrAuth[d] = (uid_parent, s_off)
        if d in A.DocKey:
            B.DocKey[d] = A.DocKey[d]
    B.aid = aid


def Search(w, user, server):
    results = []
    tokens = []
    for d, (Kd, Kd_enc) in user.DocKey.items():
        b = prf_scalar(str(Kd).encode(), w.encode())
        if user.UsrAuth.get(d) is None:
            Fu_d = prf_scalar(user.Ku, d.encode())
            scalar_stk = (b * Fu_d) % n
            stk_point = scalar_point_bytes(scalar_stk)
            uid = hmac_sha256(user.Kutilde, d.encode()).hex()
            tokens.append((uid, ("sdu", scalar_stk, stk_point, d)))
        else:
            uid, s_off = user.UsrAuth[d]
            scalar_stk = (s_off * b) % n
            stk_point = scalar_point_bytes(scalar_stk)
            tokens.append((uid, ("off", scalar_stk, stk_point, d)))
    aid = user.aid
    for uid, token in tokens:
        U = server.USet.get(uid, None)
        if U is None:
            continue
        alpha_chain = 1
        if aid and aid in server.ASet:
            alpha_chain = server.ASet[aid][0]
        if token[0] == "sdu":
            scalar_stk = token[1]
            scalar_x = (scalar_stk * U) % n
            Xb = scalar_point_bytes(scalar_x)
            if Xb in server.XSet:
                Yb = server.XSet[Xb]
                nonce = Yb[:12]
                ct_tag = Yb[12:]
                try:
                    d_plain = AESGCM(user.DocKey[token[3]][1]).decrypt(nonce, ct_tag, None).decode()
                except Exception:
                    d_plain = "<dec failed>"
                results.append(d_plain)
        else:
            scalar_stk = token[1]
            exponent = (U * alpha_chain) % n
            scalar_x = (scalar_stk * exponent) % n
            Xb = scalar_point_bytes(scalar_x)
            if Xb in server.XSet:
                Yb = server.XSet[Xb]
                nonce = Yb[:12]
                ct_tag = Yb[12:]
                try:
                    d_plain = AESGCM(user.DocKey[token[3]][1]).decrypt(nonce, ct_tag, None).decode()
                except Exception:
                    d_plain = "<dec failed>"
                results.append(d_plain)
    return list(dict.fromkeys(results))

# Demo
do = DataOwner()
SK, server = do.setup()
do.add_docs([("d1", ["budget"])], SK, server)
A = User("A"); B = User("B"); D = User("D")
A.enroll(); B.enroll(); D.enroll()
OnlineAuth_DO_to_user(do, server, SK, A, ["d1"])
OfflineAuth_A_to_B(server, A, B, ["d1"])
res_B = Search("budget", B, server)
res_D = Search("budget", D, server)
print("Authorized B search results:", res_B)
print("Unauthorized D search results:", res_D)
print("Server ASet keys:", list(server.ASet.keys()))
print("Server USet keys:", list(server.USet.keys()))
print("Number of XSet entries:", len(server.XSet))
