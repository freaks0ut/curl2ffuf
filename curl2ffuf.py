#!/usr/bin/env python3
import shlex
import sys
import re
import argparse
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

def unquote_token(t: str) -> str:
    t = t.strip()

    # Burp ANSI-C quoting: $'...'
    if len(t) >= 3 and t.startswith("$'") and t.endswith("'"):
        t = t[2:-1]
    elif len(t) >= 2 and t.startswith("'") and t.endswith("'"):
        t = t[1:-1]
    elif len(t) >= 3 and t.startswith('$"') and t.endswith('"'):
        t = t[2:-1]
    elif len(t) >= 2 and t.startswith('"') and t.endswith('"'):
        t = t[1:-1]

    # Sometimes Burp exports values like $POST / $Host: ...
    # If it looks like a leftover "$" prefix, strip it.
    if t.startswith("$") and not ("http://" in t or "https://" in t):
        t = t[1:]

    return t


def parse_curl(cmd: str):
    tokens = [unquote_token(x) for x in shlex.split(cmd)]

    method = "GET"
    url = None
    headers = []
    data = None
    cookie = None

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok == "curl":
            i += 1
            continue

        if tok in ("-X", "--request") and i + 1 < len(tokens):
            method = unquote_token(tokens[i + 1]).upper().lstrip("$")
            i += 2
            continue

        if tok in ("-H", "--header") and i + 1 < len(tokens):
            h = unquote_token(tokens[i + 1])
            # strip stray '$' if any
            if h.startswith("$"):
                h = h[1:]
            headers.append(h)
            i += 2
            continue

        if tok in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
            data = unquote_token(tokens[i + 1])
            if method == "GET":
                method = "POST"
            i += 2
            continue

        if tok in ("-b", "--cookie") and i + 1 < len(tokens):
            cookie = unquote_token(tokens[i + 1])
            if cookie.startswith("$"):
                cookie = cookie[1:]
            i += 2
            continue

        if "http://" in tok or "https://" in tok:
            m = re.search(r"(https?://\S+)", tok)
            url = m.group(1) if m else tok
            i += 1
            continue

        i += 1

    if cookie:
        headers.append(f"Cookie: {cookie}")

    # If no explicit -X but we have body, assume POST
    if data and method == "GET":
        method = "POST"

    return method, url, headers, data


def fuzz_query(url: str, param: str | None = None) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return url

    if param:
        params = [(k, "FUZZ" if k == param else v) for k, v in params]
    else:
        params[0] = (params[0][0], "FUZZ")

    return urlunparse(parsed._replace(query=urlencode(params)))


def fuzz_body(data: str, param: str | None = None) -> str:
    if not data:
        return data
    if param:
        pattern = rf"({re.escape(param)}=)[^&]*"
        return re.sub(pattern, r"\1FUZZ", data)
    return re.sub(r"=([^&]*)", "=FUZZ", data, count=1)


def build_ffuf(method, url, headers, data, wordlist, param):
    # fuzz location
    out_url = fuzz_query(url, param) if method == "GET" else url

    # shell-safe quoting
    cmd = ["ffuf", "-u", shlex.quote(out_url), "-X", shlex.quote(method)]

    for h in headers:
        cmd += ["-H", shlex.quote(h)]

    if method in ("POST", "PUT", "PATCH") and data:
        cmd += ["-d", shlex.quote(fuzz_body(data, param))]

    cmd += ["-w", shlex.quote(wordlist)]
    return " ".join(cmd)


def main():
    p = argparse.ArgumentParser(
        prog="curl2ffuf",
        description="Convert a curl command into an ffuf command (GET/POST + headers + cookies + body).",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("curl", help="Full curl command (wrap in quotes)")
    p.add_argument("-w", "--wordlist", default="wordlist.txt", help="ffuf wordlist (default: wordlist.txt)")
    p.add_argument("-p", "--param", help="Parameter name to fuzz (default: first parameter)")
    args = p.parse_args()

    method, url, headers, data = parse_curl(args.curl)
    if not url:
        print("[-] No URL found in curl command")
        sys.exit(1)

    print(build_ffuf(method, url, headers, data, args.wordlist, args.param))


if __name__ == "__main__":
    main()