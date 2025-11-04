# Retry: corrected DSSEHA prototype using P-256 curve and AES-GCM (simplified, educational)
import random
import hmac
import time

from Crypto.Cipher import AES
import gmpy2
from gmpy2 import mpz
from web3 import Web3
import json
import os


random_length = 128
g1=mpz(2141434891434191460597654106285009794456474073127443963580690795002163321265105245635441519012876162226508712450114295048769820153232319693432987768769296824615642594321423205772115298200265241761445943720948512138315849294187201773718640619332629679913150151901308086084524597187791163240081868198195818488147354220506153752944012718951076418307414874651394412052849270568833194858516693284043743223341262442918629683831581139666162694560502910458729378169695954926627903314499763149304778624042360661276996520665523643147485282255746183568795735922844808611657078638768875848574571957417538833410931039120067791054495394347033677995566734192953459076978334017849678648355479176605169830149977904762004245805443987117373895433551186090322663122981978369728727863969397652199851244115246624405814648225543311628517631088342627783146899971864519981709070067428217313779897722021674599747260345113463261690421765416396528871227)
p = mpz(3268470001596555685058361448517594259852327289373621024658735136696086397532371469771539343923030165357102680953673099920140531685895962914337283929936606946054169620100988870978124749211273448893822273457310556591818639255714375162549119727203843057453108725240320611822327564102565670538516259921126103868685909602654213513456013263604608261355992328266121535954955860230896921190144484094504405550995009524584190435021785232142953886543340776477964177437292693777245368918022174701350793004000567940200059239843923046609830997768443610635397652600287237380936753914127667182396037677536643969081476599565572030244212618673244188481261912792928641006121759661066004079860474019965998840960514950091456436975501582488835454404626979061889799215263467208398224888341946121760934377719355124007835365528307011851448463147156027381826788422151698720245080057213877012399103133913857496236799905578345362183817511242131464964979)
q = mpz(93911948940456861795388745207400704369329482570245279608597521715921884786973)

# 生成指定长度的随机串，返回16进制字符串
def random_string(random_string_length):
    seed = "01"
    sa = []
    for i in range(random_string_length):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    salt_hex = hex(int(salt, 2))
    return salt_hex


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
        self.K1 = random_string(random_length)
        self.K2 = random_string(random_length)
        self.K3 = random_string(random_length)
        # self.K1 = secrets.token_bytes(32)
        # self.K2 = secrets.token_bytes(32)
        # self.K3 = secrets.token_bytes(32)
        self.doc_keys = {}  # d -> (Kd scalar, Kd_tilde scalar, Kd_enc bytes)

    def setup(self):
        return (self.K1, self.K2, self.K3), Server()

    def add_docs(self, DOC, SK, server):
        K1,K2,K3 = SK
        for d, kws in DOC:
            Kd = hmac.new(K1.encode(), d.encode(), digestmod='md5').digest()
            # Kd = prf_scalar(K1, d.encode())
            Kd_tilde = hmac.new(K2.encode(), d.encode(), digestmod='md5').digest()
            Kd_enc = hmac.new(K3.encode(), d.encode(), digestmod='md5').digest()
            self.doc_keys[d] = (Kd, Kd_tilde, Kd_enc)
            for w in kws:
                a = hmac.new(Kd_tilde, d.encode(), digestmod='md5').digest()
                b = hmac.new(Kd, w.encode(), digestmod='md5').digest()
                #b = prf_scalar(Kd.to_bytes(32, "big"), w.encode())
                aa = int.from_bytes(a, byteorder='big', signed=False)
                bb = int.from_bytes(b, byteorder='big', signed=False)
                aa_bb = ((mpz(aa) % q) * mpz(bb) % q) % q
                Xb = gmpy2.powmod(g1, mpz(aa_bb), p)
                aes = AES.new(key=Kd_enc, mode=AES.MODE_ECB)
                Yb = aes.encrypt(d.zfill(16).encode('utf-8'))
                server.add_X(Xb, Yb) #notice

class User:
    def __init__(self, uid):
        self.uid = uid.encode()
        self.Ku = random_string(random_length)
        self.Kutilde = random_string(random_length)
        self.UsrAuth = {}  # d -> None or (uid_hex, offtok_scalar)
        self.DocKey = {}   # d -> (Kd scalar, Kd_enc bytes)
        self.aid = None

    def enroll(self):
        return (self.Ku, self.Kutilde), {'UsrAuth': self.UsrAuth, 'DocKey': self.DocKey, 'aid': self.aid}

def OnlineAuth_DO_to_user(do, server, SK, user, IND):
    K1,K2,K3 = SK
    for d in IND:
        Kd, Kd_tilde, Kd_enc = do.doc_keys[d]
        uid = hmac.new(user.Kutilde.encode(), d.encode(), digestmod='md5').digest()
        val1 = hmac.new(Kd_tilde, d.encode(), digestmod='md5').digest() #notice
        val2 = hmac.new(user.Ku.encode(), d.encode(), digestmod='md5').digest()
        val2_int = int.from_bytes(val2, byteorder='big', signed=False)
        inv_val2 = gmpy2.invert(mpz(val2_int), q)
        U = ((mpz(int.from_bytes(val1, byteorder='big', signed=False)) % q) * (mpz(inv_val2) % q)) % q
        # U = Web3.to_bytes(hexstr=hex(int(U)))
        server.add_U(uid, U)
        user.DocKey[d] = (Kd, Kd_enc)
        user.UsrAuth[d] = None  # sDU

def OfflineAuth_A_to_B(server, A, B, IND):
    # ① 用户级别计算（放循环外）
    aid = hmac.new(A.Kutilde.encode(), B.uid, digestmod='md5').digest()
    alpha = hmac.new(A.Ku.encode(), B.uid, digestmod='md5').digest()
    alpha_int = int.from_bytes(alpha, byteorder='big', signed=False)
    alpha_inv = gmpy2.invert(mpz(alpha_int), q)
    # ② 根据 A 的类型更新 ASet
    parent_aid = A.aid if A.aid else None
    server.add_A(aid, alpha_inv, parent_aid=parent_aid)

    # ③ 对每个文档生成 offtok
    for d in IND:
        if A.UsrAuth.get(d) is None:
            # A 是 sDU
            termA_d = hmac.new(A.Ku.encode(), d.encode(), digestmod='md5').digest()
            termA_uB = hmac.new(A.Ku.encode(), B.uid, digestmod='md5').digest()
            A_d = int.from_bytes(termA_d, byteorder='big', signed=False)
            A_uB = int.from_bytes(termA_uB, byteorder='big', signed=False)
            s_off = ((mpz(A_d) % q) * (mpz(A_uB) % q)) % q
            s_off = gmpy2.powmod(g1, mpz(s_off), p)
        else:
            uid_parent, s_parent = A.UsrAuth[d]
            termA_uB = hmac.new(A.Ku.encode(), B.uid.encode(), digestmod='md5').digest()
            termA_uB = int.from_bytes(termA_uB, byteorder='big', signed=False)
            termA_uB = mpz(termA_uB) % q
            s_off = gmpy2.powmod(mpz(s_parent), mpz(termA_uB), p) #notice

        uid_parent = (
            hmac.new(A.Kutilde.encode(), d.encode(), digestmod='md5').digest()
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
        b = hmac.new(Kd, w.encode(), digestmod='md5').digest()
        if user.UsrAuth.get(d) is None:
            Fu_d = hmac.new(user.Ku.encode(), d.encode(), digestmod='md5').digest()
            bb = int.from_bytes(b, byteorder='big', signed=False)
            fudd = int.from_bytes(Fu_d, byteorder='big', signed=False)
            stkd = ((mpz(bb) % q) * (mpz(fudd) % q)) % q
            stk_point = gmpy2.powmod(g1, mpz(stkd), p)
            uid = hmac.new(user.Kutilde.encode(), d.encode(), digestmod='md5').digest()
            tokens.append((uid, stk_point, Kd_enc))
        else:
            uid, s_off = user.UsrAuth[d]
            bb = int.from_bytes(b, byteorder='big', signed=False)
            bb = mpz(bb) % q
            stk_point = gmpy2.powmod(s_off, mpz(bb), p)
            tokens.append((uid, stk_point, Kd_enc))
    aid = user.aid
    for token in tokens:
        uid = token[0]
        U = server.USet.get(uid, None)
        stkd = token[1]
        # uu = int.from_bytes(U, byteorder='big', signed=False)
        uu = mpz(U) % q
        x = gmpy2.powmod(stkd, uu, p)
        if aid and aid in server.ASet:
            alpha_chain = server.ASet[aid][0]
            # alpha_chain = int.from_bytes(alpha_chain, byteorder='big', signed=False)
            alpha_chain = mpz(alpha_chain) % q
            x = gmpy2.powmod(x, alpha_chain, p)
        if x in server.XSet:
            Y = server.XSet[x]
            aes = AES.new(key=token[2], mode=AES.MODE_ECB)
            d_plain = aes.decrypt(Y).decode('utf-8')
            results.append(d_plain)
    return list(dict.fromkeys(results))

# Demo
do = DataOwner()
SK, server = do.setup()
do.add_docs([("d1", ["budget", "rom"]), ("d2", ["rom"])], SK, server)
A = User("A"); B = User("B"); D = User("D")
A.enroll(); B.enroll(); D.enroll()
OnlineAuth_DO_to_user(do, server, SK, A, ["d1", "d2"])
OfflineAuth_A_to_B(server, A, B, ["d1", "d2"])
OfflineAuth_A_to_B(server, A, D, ["d2"])
res_B = Search("budget", B, server)
res_D = Search("rom", D, server)
print("Authorized B search results:", res_B)
print("Unauthorized D search results:", res_D)
print("Server ASet keys:", list(server.ASet.keys()))
print("Server USet keys:", list(server.USet.keys()))
print("Number of XSet entries:", len(server.XSet))
