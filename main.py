import argparse, requests, random, os, sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from termcolor import colored

# === BANNER ===
def show_banner():
    banner = r"""
 ███████████                                                █████   █████                                    █████
░░███░░░░░███                                              ░░███   ░░███                                    ░░███ 
 ░███    ░███  ██████   ████████   ██████   █████████████   ░███    ░███   ██████  █████ ████ ████████    ███████ 
 ░██████████  ░░░░░███ ░░███░░███ ░░░░░███ ░░███░░███░░███  ░███████████  ███░░███░░███ ░███ ░░███░░███  ███░░███ 
 ░███░░░░░░    ███████  ░███ ░░░   ███████  ░███ ░███ ░███  ░███░░░░░███ ░███ ░███ ░███ ░███ ░███ ░███ ░███ ░███ 
 ░███         ███░░███  ░███      ███░░███  ░███ ░███ ░███  ░███    ░███ ░███ ░███ ░███ ░███ ░███ ░███ ░███ ░███ 
 █████       ░░████████ █████    ░░████████ █████░███ █████ █████   █████░░██████  ░░████████ ████ █████░░████████
░░░░░         ░░░░░░░░ ░░░░░      ░░░░░░░░ ░░░░░ ░░░ ░░░░░ ░░░░░   ░░░░░  ░░░░░░    ░░░░░░░░ ░░░░ ░░░░░  ░░░░░░░░ 

                [ ParamHound ] - Smart Parameter Finder for Manual SQLi/XSS Testing
                          Tool created by SCARSEC
"""
    print(colored(banner, "cyan", attrs=["bold"]))

# === User‑Agent pool ===
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X)",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F)",
]

# === trackers ===
visited_urls, seen_forms = set(), set()
stats = {"visited": 0, "forms": 0, "params": 0}

def is_interesting_param(name):
    # List of relevant keywords for SQLi/XSS testing
    relevant_keywords = ["id", "query", "search", "username", "email", "input", "q", "param"]
    # List of unwanted keywords (like tokens, session IDs, etc.)
    unwanted_keywords = ["token", "session", "csrf", "auth", "password", "captcha", "nonce", "timestamp"]

    # Check if any relevant keyword is in the parameter name and it is not an unwanted keyword
    return any(k in name.lower() for k in relevant_keywords) and not any(k in name.lower() for k in unwanted_keywords)

# --- extractors --------------------------------------------------------------
def extract_forms(url, session, out, only_forms, only_post, only_get):
    try:
        soup = BeautifulSoup(session.get(url, timeout=10).text, "html.parser")
        forms = soup.find_all("form")
        if forms: stats["forms"] += len(forms)
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").upper()
            if only_get and method != "GET": continue
            if only_post and method != "POST": continue
            inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
            sig = (method, action, tuple(sorted(inputs)))
            if sig in seen_forms: continue
            seen_forms.add(sig)
            data = f"\n[+] Form Found on {url}\n    Method: {method}\n    Action: {action}\n    Inputs: {', '.join(inputs)}\n"
            print(colored(data, "green"))
            if out: out.write(data); out.flush()
            for n in inputs:
                if is_interesting_param(n):  # Only print if it's an interesting parameter
                    note = colored(f"    ⚠️  Potential vulnerable param: {n}", "yellow")
                    print(note)
                    if out: out.write(note + "\n"); out.flush()
    except Exception as e:
        print(colored(f"[x] Error extracting forms from {url}: {e}", "red"))

def extract_get_parameters(url, session, out, only_get, only_params):
    parsed = urlparse(url)
    if parsed.query:
        stats["params"] += 1
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = [p.split('=') for p in parsed.query.split('&')]
        full = base + '?' + urlencode(params)
        result = f"\n[+] GET URL Found: {full}\n    Params: {', '.join(p[0] for p in params)}\n"
        print(colored(result, "blue"))
        if out: out.write(result); out.flush()
        print(colored(f"    [*] Full URL to Test in Browser: {full}", "cyan"))
        for n, _ in params:
            if is_interesting_param(n):  # Only print if it's an interesting parameter
                note = colored(f"    ⚠️  Potential vulnerable param: {n}", "yellow")
                print(note)
                if out: out.write(note + "\n"); out.flush()

# --- crawler -----------------------------------------------------------------
def crawl(url, session, out, depth=1):
    if url in visited_urls or depth > 10: return
    visited_urls.add(url)
    stats["visited"] += 1
    print(colored(f"[~] Crawling: {url}", "magenta"))
    try:
        soup = BeautifulSoup(session.get(url, timeout=10).text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if not href or href.startswith("#"): continue  # Skip empty or hash links
            href = urljoin(url, href)

            # Validate the href (must be a valid URL)
            parsed_href = urlparse(href)
            if not parsed_href.netloc or not parsed_href.path:
                continue  # Skip malformed or incomplete URLs

            # Handle invalid or non-string sequences in hrefs
            if not isinstance(href, str):
                print(colored(f"[x] Invalid URL skipped: {href}", "red"))
                continue

            # Proceed if it's a valid internal link
            if parsed_href.netloc == urlparse(url).netloc:
                extract_forms(href, session, out, args.only_forms, args.only_post, args.only_get)
                if not args.only_post:
                    extract_get_parameters(href, session, out, args.only_get, args.only_params)
                crawl(href, session, out, depth + 1)
    except Exception as e:
        print(colored(f"[x] Error crawling {url}: {e}", "red"))

# --- main --------------------------------------------------------------------
if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="[paramhound] - Smart Parameter Finder for Manual SQLi/XSS Testing\nTool created by SCARSEC",
        formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-o", "--output")
    p.add_argument("--crawl", help="Enable crawling (use: all)")
    p.add_argument("--user-agent")
    p.add_argument("--random-agent", action="store_true")
    p.add_argument("--only-forms", action="store_true")
    p.add_argument("--only-get", action="store_true")
    p.add_argument("--only-post", action="store_true")
    p.add_argument("--only-params", action="store_true")
    args = p.parse_args()

    show_banner()

    headers = {'User-Agent': random.choice(USER_AGENTS) if args.random_agent else args.user_agent or USER_AGENTS[0]}
    session = requests.Session()
    session.headers.update(headers)

    out = None
    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True) if os.path.dirname(args.output) else None
        out = open(args.output, "w")

    try:
        if args.crawl == "all":
            crawl(args.url, session, out)
        else:
            # Only show forms if not specifically restricted by get or post
            if not args.only_get and not args.only_post:
                extract_forms(args.url, session, out, args.only_forms, args.only_post, args.only_get)
                extract_get_parameters(args.url, session, out, args.only_get, args.only_params)
            if args.only_get:
                extract_get_parameters(args.url, session, out, args.only_get, args.only_params)
            if args.only_post:
                extract_forms(args.url, session, out, args.only_forms, args.only_post, args.only_get)
                
        print(colored("\n[+] Scan Summary", "cyan", attrs=["bold"]))
        print(f"    Total URLs visited : {stats['visited']}")
        print(f"    GET URLs found     : {stats['params']}")
        print(f"    Forms extracted    : {stats['forms']}\n")
    except KeyboardInterrupt:
        print("\nProcess interrupted")
    finally:
        if out: out.close()
