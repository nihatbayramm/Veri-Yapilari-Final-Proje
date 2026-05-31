class TSTNode:
    def __init__(self, c):
        self.c = c
        self.left = self.right = self.mid = None
        self.is_malicious = False
        self.threat_type = None


class ThreatIntelTST:
    def __init__(self):
        self.root = None
        self.domain_count = 0
        self.node_count = 0

    def _reverse_domain(self, domain):
        return '.'.join(reversed(domain.lower().strip().split('.')))

    def _insert(self, node, word, idx, threat_type):
        c = word[idx]
        if node is None:
            node = TSTNode(c)
            self.node_count += 1
        if c < node.c:
            node.left = self._insert(node.left, word, idx, threat_type)
        elif c > node.c:
            node.right = self._insert(node.right, word, idx, threat_type)
        else:
            if idx + 1 == len(word):
                node.is_malicious = True
                node.threat_type = threat_type
            else:
                node.mid = self._insert(node.mid, word, idx + 1, threat_type)
        return node

    def add_threat(self, domain, threat_type="MALWARE"):
        rev = self._reverse_domain(domain)
        self.root = self._insert(self.root, rev, 0, threat_type)
        self.domain_count += 1

    def _search(self, node, word, idx):
        if node is None or idx >= len(word):
            return None
        c = word[idx]
        if c < node.c:
            return self._search(node.left, word, idx)
        elif c > node.c:
            return self._search(node.right, word, idx)
        else:
            if node.is_malicious:
                return node.threat_type   # ebeveyn domain zararlı
            if idx + 1 == len(word):
                return node.threat_type if node.is_malicious else None
            return self._search(node.mid, word, idx + 1)

    def check_domain(self, domain):
        rev = self._reverse_domain(domain)
        # Alt-domain kontrolü: her prefix seviyesinde ara
        parts = rev.split('.')
        for i in range(len(parts)):
            prefix = '.'.join(parts[:i+1])
            result = self._search(self.root, prefix, 0)
            if result:
                return True, result
        return False, None

    def stats(self):
        return f"TST düğüm sayısı: {self.node_count} | Kayıtlı tehdit: {self.domain_count}"


if __name__ == "__main__":
    import time
    print("=== Zararlı Domain Tespit Testi ===\n")

    tst = ThreatIntelTST()

    threats = [
        ("evil.com",          "PHISHING"),
        ("malware-cdn.net",   "MALWARE_C2"),
        ("botnet.xyz",        "BOTNET"),
        ("phish-bank.com",    "PHISHING"),
        ("ransomware.io",     "RANSOMWARE"),
    ]

    print(f"Yükleniyor: {len(threats)} tehdit kaydı...")
    for domain, ttype in threats:
        tst.add_threat(domain, ttype)
    print(tst.stats())
    print()

    queries = [
        "google.com",
        "evil.com",
        "sub.evil.com",         
        "login.phish-bank.com",  
        "github.com",
        "botnet.xyz",
        "cdn.malware-cdn.net",   
    ]

    print("[ Domain Sorguları ]")
    for domain in queries:
        t0 = time.perf_counter()
        is_bad, threat = tst.check_domain(domain)
        elapsed = (time.perf_counter() - t0) * 1000
        status = f"TEHDIT [{threat}]" if is_bad else "TEMİZ"
        print(f"  {domain:<30} -> {status:<20} [{elapsed:.3f}ms]")