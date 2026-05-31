import time
import random
import string

def compute_failure(pattern):
    f = [0] * len(pattern)
    k = 0
    for i in range(1, len(pattern)):
        while k > 0 and pattern[k] != pattern[i]:
            k = f[k - 1]
        if pattern[k] == pattern[i]:
            k += 1
        f[i] = k
    return f

def kmp_search(text, pattern):
    if not pattern:
        return []
    f = compute_failure(pattern)
    matches = []
    q = 0
    for i, c in enumerate(text):
        while q > 0 and pattern[q] != c:
            q = f[q - 1]
        if pattern[q] == c:
            q += 1
        if q == len(pattern):
            matches.append(i - len(pattern) + 1)
            q = f[q - 1]
    return matches

def naive_search(text, pattern):
    matches = []
    n, m = len(text), len(pattern)
    for i in range(n - m + 1):
        if text[i:i+m] == pattern:
            matches.append(i)
    return matches

def scan_log_file(log_lines, signatures):
    alerts = []
    for lineno, line in enumerate(log_lines, 1):
        normalized = line.lower()
        for sig in signatures:
            hits = kmp_search(normalized, sig.lower())
            if hits:
                alerts.append({
                    "line": lineno,
                    "signature": sig,
                    "positions": hits,
                    "content": line[:80]
                })
    return alerts

def generate_fake_log(num_lines=500, inject_attacks=True):
    normal = [
        'GET /index.html HTTP/1.1 200',
        'POST /api/login HTTP/1.1 401',
        'GET /static/main.css HTTP/1.1 200',
        'GET /dashboard HTTP/1.1 200',
        'POST /api/data HTTP/1.1 200',
    ]
    attacks = [
        "GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1",
        "GET /../../../etc/passwd HTTP/1.1 200",
        "POST /comment body=<script>alert('xss')</script>",
        "GET /cmd?exec=cmd.exe /c whoami HTTP/1.1",
        "GET /page?id=1; DROP TABLE users; HTTP/1.1",
    ]
    lines = []
    for _ in range(num_lines):
        lines.append(random.choice(normal))
    if inject_attacks:
        positions = random.sample(range(num_lines), min(8, num_lines))
        for pos in positions:
            lines[pos] = random.choice(attacks)
    return lines


# ─── TEST ───
if __name__ == "__main__":
    print("=== KMP Log Tarama Testi ===\n")

    signatures = [
        "SELECT * FROM",
        "UNION SELECT",
        "../../../etc/passwd",
        "<script>",
        "cmd.exe /c",
        "DROP TABLE",
    ]

    log = generate_fake_log(500)
    print(f"Log boyutu: {len(log)} satır")
    print(f"İmza sayısı: {len(signatures)}\n")

    # KMP
    t0 = time.perf_counter()
    alerts = scan_log_file(log, signatures)
    kmp_time = (time.perf_counter() - t0) * 1000

    # Naif karşılaştırma
    t0 = time.perf_counter()
    for line in log:
        for sig in signatures:
            naive_search(line.lower(), sig.lower())
    naive_time = (time.perf_counter() - t0) * 1000

    print(f"KMP    -> {kmp_time:.2f} ms")
    print(f"Naif   -> {naive_time:.2f} ms")
    print(f"Hız farkı: {naive_time/kmp_time:.1f}x\n")

    print(f"[ {len(alerts)} Uyarı Bulundu ]\n")
    for a in alerts:
        print(f"  Satır {a['line']:>3}: [{a['signature']}]")
        print(f"           {a['content']}")