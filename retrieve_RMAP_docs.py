import json, base64, secrets, ssl, urllib.request, sys, types, os
# pgpy imports stdlib 'imghdr', removed in Python 3.13
sys.modules.setdefault("imghdr", types.ModuleType("imghdr")).what = lambda *a, **k: None
import pgpy
from pgpy.types import Armorable

GROUPS     = range(1, 31)
IDENTITY   = "Group_29"
MY_PRIV    = "../pgp_keys/server_priv.asc"
KEYS_DIR   = "../pgp_keys/clients_dir"
OUTDIR     = "pdfs"
TIMEOUT    = 15

def strip(a):
    L = [l for l in a.strip().splitlines() if not l.startswith("-----")]
    if "" in L: L = L[L.index("") + 1:]
    if L and L[-1].startswith("="): L = L[:-1]
    return "".join(L)

def wrap(p):
    crc = base64.b64encode(Armorable.crc24(bytearray(base64.b64decode(p))).to_bytes(3, "big")).decode()
    body = "\n".join(p[i:i+64] for i in range(0, len(p), 64))
    return f"-----BEGIN PGP MESSAGE-----\n\n{body}\n={crc}\n-----END PGP MESSAGE-----\n"

def post(server, path, obj):
    req = urllib.request.Request(server + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=TIMEOUT).read())

def fetch(url):
    return urllib.request.urlopen(url, timeout=TIMEOUT).read()

def decrypt(blob, priv):
    msg = pgpy.PGPMessage.from_blob(wrap(blob))
    return json.loads(priv.decrypt(msg).message)

def run(n):
    tag    = f"Group_{n:02d}"
    server = f"http://softsec-group-{n:02d}.dsv.local.su.se:5000"
    pub, _ = pgpy.PGPKey.from_file(os.path.join(KEYS_DIR, tag + ".asc"))
    priv, _ = pgpy.PGPKey.from_file(MY_PRIV)
    
    ## encryption lambda function
    enc = lambda d: {"payload": strip(str(pub.encrypt(pgpy.PGPMessage.new(json.dumps(d)))))}

    nc = secrets.randbits(64)
    ## initiate handshake and send nonce and identity encrypted with public key
    msg1 = post(server, "/api/rmap-initiate",
                      enc({"identity": IDENTITY, "nonceClient": nc}) 
                      )
    ## decrypt msg1 from sever with private key
    msg1_decrypted = decrypt(msg1["payload"], priv)
    
    ## get sever nonce
    server_nonce = msg1_decrypted["nonceServer"]
    
    ## resend server nonce encrypted
    msg2 = post(server, "/api/rmap-get-link", enc({"nonceServer": server_nonce}))
    
    ## decrypt servers reply with private key
    msg2_decrypted = decrypt(msg2["payload"], priv)
    
    ## extract the link
    msg2_link = msg2_decrypted["result"]
    
    link = f"{nc:016x}{server_nonce:016x}"
    print(f"  result: {msg2_link}\n  link:   {link}")

    ## constact URL and fetch
    url = f"{server}/api/get-version/{link}"
    try:
        pdf = fetch(url)
    except Exception as e:
        print(f"  try {url} -> {e}")
    if pdf[:5] == b"%PDF-":
        dest = os.path.join(OUTDIR, tag + ".pdf")
        with open(dest, "wb") as f: f.write(pdf)
        print(f"  saved: {dest} ({len(pdf)} bytes) via {url}")
        return True
    return False

if __name__ == "__main__":
    os.makedirs(OUTDIR, exist_ok=True)
    ok, failed = [], []
    for n in GROUPS:
        print(f"== Group_{n:02d} (port 5000) ==")
        try:
            (ok if run(n) else failed).append(n)
        except Exception as e:
            print(f"  (failed) {type(e).__name__}: {e}")
            failed.append(n)
    print(f"\nDone. PDFs: {len(ok)}  failed: {[f'{n:02d}' for n in failed]}")