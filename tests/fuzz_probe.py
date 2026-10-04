"""Throws malformed and hostile messages at the analyzer and prints anything that raises or runs slowly, and how disguised
versions of known attacks score. Not part of the suite; run:  python tests/fuzz_probe.py"""
import base64
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from phishing_analyzer.analyzer import analyze_email

HDR = "From: A <a@example.org>\nTo: b@example.org\nSubject: hi\nDate: Thu, 24 Sep 2026 09:30:00 +0000\n"


def nested_multipart(depth):
    body = "Content-Type: text/plain\n\nhello"
    for i in range(depth):
        b = f"b{i}"
        body = f'Content-Type: multipart/mixed; boundary="{b}"\n\n--{b}\n{body}\n--{b}--'
    return HDR + "MIME-Version: 1.0\n" + body


def nested_rfc822(depth):
    inner = HDR + "\nend"
    for _ in range(depth):
        inner = HDR + 'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="X"\n\n--X\nContent-Type: message/rfc822\n\n' + inner + "\n--X--"
    return inner


CASES = {
    "headers only": HDR,
    "no blank line": "From: a@b.com",
    "just a colon": ":",
    "bad charset": HDR + "Content-Type: text/plain; charset=nonsense-9\n\nvérify your account now: http://x.example/login",
    "bad base64": HDR + "Content-Transfer-Encoding: base64\nContent-Type: text/plain\n\n!!!notbase64===",
    "bad encoded-word subject": "From: a@b.com\nSubject: =?utf-8?b?!!!?= =?bogus?q?x?=\n\nbody",
    "nul bytes": HDR + "\nverify your account\x00\x00 http://a.example/x",
    "lone surrogate": HDR + "\nverify your account \ud800 http://a.example/x",
    "5000 links": HDR + "\n" + "\n".join(f"http://host{i}.example.com/p" for i in range(5000)),
    "1MB single line": HDR + "\n" + "A" * 1_000_000,
    "1.9MB text": HDR + "\n" + ("verify your account now " * 80_000),
    "nested multipart 60": nested_multipart(60),
    "nested rfc822 30": nested_rfc822(30),
    "mixed line endings": HDR.replace("\n", "\r\n") + "\rverify your\r\naccount\n",
    "huge subject": "From: a@b.com\nSubject: " + "x" * 200_000 + "\n\nbody",
    "10k headers": "From: a@b.com\n" + "\n".join(f"X-H{i}: v" for i in range(10_000)) + "\n\nbody",
    "javascript href": HDR + 'Content-Type: text/html\n\n<a href="javascript:alert(1)">x</a><a href="data:text/html;base64,PHNjcmlwdD4=">y</a><meta http-equiv="refresh" content="0;url=http://e.example/">',
    "empty attachment": HDR + 'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nhi\n--B\nContent-Type: application/pdf; name="a.pdf"\nContent-Disposition: attachment; filename="a.pdf"\nContent-Transfer-Encoding: base64\n\n\n--B--',
    "zip bomb-ish": None,  # filled below
}

# a deeply repeated zip entry list
import io
import zipfile

bio = io.BytesIO()
with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("big.txt", b"\0" * 50_000_000)
    for i in range(2000):
        z.writestr(f"f{i}.txt", b"x")
b64 = base64.encodebytes(bio.getvalue()).decode()
CASES["zip bomb-ish"] = HDR + 'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nsee zip\n--B\nContent-Type: application/zip; name="a.zip"\nContent-Disposition: attachment; filename="a.zip"\nContent-Transfer-Encoding: base64\n\n' + b64 + "\n--B--"

print("=== robustness")
for name, raw in CASES.items():
    t0 = time.time()
    try:
        r = analyze_email(raw, network_enabled=False)
        status = f"ok risk={r.risk} score={r.score}"
    except Exception as e:  # noqa: BLE001
        status = "EXCEPTION " + "".join(traceback.format_exception_only(type(e), e)).strip()[:110]
    dt = time.time() - t0
    print(f"{'SLOW ' if dt > 3 else '     '}{dt:5.1f}s  {name:26} {status}")

print("\n=== disguised versions (want at least suspicious)")
DISGUISED = {
    "zero-width split keywords": HDR + "\nPlease ve\u200brify your acc\u200bount now: https://secure-login.example.com/verify",
    "homoglyph keywords (cyrillic a/e/o)": HDR + "\nPlеаse vеrify yоur аccоunt: https://secure-login.example.com/verify",
    "seed phrase, spaced": HDR + "\nTo restore your wallet, enter your s e e d   p h r a s e at https://wallet-restore.example.com",
    "seed phrase, negated (must stay low)": HDR + "\nNever enter your seed phrase on any website. We will never ask for your recovery phrase.",
    "payroll, plain": HDR + "\nHi, please update my direct deposit to the new account below before the next payroll run.",
    "payroll, HR notice (must stay low)": HDR + "\nYour direct deposit was updated as requested. If you did not make this change, contact HR.",
    "french tax, accented": HDR.replace("hi", "Remboursement") + "\nVous avez droit à un remboursement d'impôts. Veuillez vérifier vos coordonnées bancaires avant 48 heures : http://impots-fr.example.com",
    "link mismatch via uppercase host": HDR + 'Content-Type: text/html\n\n<a href="http://Evil.Example.com/x">https://www.google.com/account</a>',
    "link mismatch via userinfo": HDR + 'Content-Type: text/html\n\n<a href="http://www.google.com@evil.example.com/x">http://www.google.com/account</a>',
    "link text is a bare domain": HDR + 'Content-Type: text/html\n\n<a href="http://evil.example.com/x">paypal.com</a>',
    "link via image only": HDR + 'Content-Type: text/html\n\n<a href="http://evil.example.com/x"><img src="cid:logo"></a> Verify your account',
}
for name, raw in DISGUISED.items():
    try:
        r = analyze_email(raw, network_enabled=False)
        print(f"  {name:40} risk={r.risk:16} score={r.score:3}  {[f.code for f in r.findings][:5]}")
    except Exception as e:  # noqa: BLE001
        print(f"  {name:40} EXCEPTION {e}")
