import sys, json, hashlib, re, requests
from concurrent.futures import ThreadPoolExecutor

def norm(body):
    b = re.sub(r'\d{10,13}', 'TS', body)
    b = re.sub(r'[0-9a-f]{16,}', 'HEX', b)
    return hashlib.sha256(b.encode()).hexdigest()

def probe(url_tpl, token, id_val, header="Authorization", scheme="Bearer"):
    url = url_tpl.replace("{id}", str(id_val))
    h = {header: f"{scheme} {token}"} if token else {}
    try:
        r = requests.get(url, headers=h, timeout=10, allow_redirects=False)
        return {"id": id_val, "status": r.status_code, "len": len(r.text),
                "hash": norm(r.text), "snippet": r.text[:120]}
    except requests.RequestException as e:
        return {"id": id_val, "error": str(e)}

def hunt(url_tpl, token, start, end, workers=8):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda i: probe(url_tpl, token, i), range(start, end)))
    ok = [r for r in results if r.get("status") == 200]
    # any 200 beyond the first is a candidate — real leak needs manual confirm
    return {"total_200": len(ok), "candidates": ok[:50], "all": results}

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("usage: idor.py URL_WITH_{id} TOKEN START_ID END_ID"); sys.exit(1)
    url, tok, a, b = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    print(json.dumps(hunt(url, tok, a, b), indent=2))