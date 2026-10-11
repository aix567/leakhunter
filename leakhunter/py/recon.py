import re, sys, json, requests
from urllib.parse import urljoin, urlparse

JS_URL_RE = re.compile(r'''(?:src|href)\s*=\s*["']([^"']+\.js[^"']*)["']''', re.I)
PATH_RE = re.compile(r'''["'`](/[a-zA-Z0-9_\-/{}.:]{2,120})["'`]''')
ABS_RE  = re.compile(r'''["'`](https?://[^\s"'`]+)["'`]''')
API_RE  = re.compile(r'''["'`](/?(?:api|v\d|graphql|rest)/[a-zA-Z0-9_\-/{}.:]+)["'`]''', re.I)

def fetch(session, url):
    try:
        r = session.get(url, timeout=10)
        if r.status_code == 200 and "javascript" in r.headers.get("content-type",""):
            return r.text
    except requests.RequestException:
        pass
    return ""

def harvest(base):
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"
    html = s.get(base, timeout=10).text
    bundles = {urljoin(base, u) for u in JS_URL_RE.findall(html)}
    bundles.add(base)
    endpoints, abs_urls, api_paths = set(), set(), set()
    for b in bundles:
        body = fetch(s, b)
        if not body: continue
        endpoints |= set(PATH_RE.findall(body))
        abs_urls  |= set(ABS_RE.findall(body))
        api_paths |= set(API_RE.findall(body))
    return {
        "base": base,
        "bundles": sorted(bundles),
        "endpoints": sorted(endpoints),
        "absolute": sorted(abs_urls),
        "api": sorted(api_paths),
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: recon.py https://target.tld"); sys.exit(1)
    print(json.dumps(harvest(sys.argv[1]), indent=2))