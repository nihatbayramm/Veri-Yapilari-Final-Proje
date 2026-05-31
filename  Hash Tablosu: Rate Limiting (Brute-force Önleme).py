import time

TABLE_SIZE = 1024
THRESHOLD = 10      
WINDOW_SIZE = 60  

class RateLimitEntry:
    def __init__(self, ip, current_time):
        self.ip = ip
        self.count = 1
        self.window_start = current_time

class RateLimiter:
    def __init__(self, size=TABLE_SIZE):
        self.size = size
        self.table = [None] * size
        self.item_count = 0

    def _hash(self, ip):
        h = 5381
        for octet in ip.split('.'):
            for ch in octet:
                h = ((h << 5) + h) + ord(ch)
        return h % self.size

    def _probe(self, ip):
        idx = self._hash(ip)
        start = idx
        while self.table[idx] is not None:
            if self.table[idx].ip == ip:
                return idx
            idx = (idx + 1) % self.size
            if idx == start:
                return -1
        return idx

    def check(self, ip):
        current_time = time.time()
        idx = self._probe(ip)

        if idx == -1:
            return "BLOCKED (tablo dolu)"

        entry = self.table[idx]

        if entry is None or entry.ip != ip:
            self.table[idx] = RateLimitEntry(ip, current_time)
            self.item_count += 1
            return "ALLOWED"

        if current_time - entry.window_start > WINDOW_SIZE:
            entry.count = 1
            entry.window_start = current_time
            return "ALLOWED"

        entry.count += 1
        if entry.count > THRESHOLD:
            return f"BLOCKED (brute-force: {entry.count} deneme)"

        return f"ALLOWED ({entry.count}/{THRESHOLD})"

    def stats(self):
        dolu = sum(1 for x in self.table if x is not None)
        load = dolu / self.size * 100
        return f"Yük faktörü: {load:.1f}% | Kayıt sayısı: {dolu}"


# ─── TEST ───
if __name__ == "__main__":
    print("=== Rate Limiting Testi ===\n")
    limiter = RateLimiter()

    print("[ Meşru kullanıcı: 3 deneme ]")
    for i in range(3):
        sonuc = limiter.check("192.168.1.10")
        print(f"  Deneme {i+1}: {sonuc}")

    print()

    print("[ Saldırgan IP: 15 deneme ]")
    for i in range(15):
        sonuc = limiter.check("10.0.0.99")
        print(f"  Deneme {i+1}: {sonuc}")

    print()

    print("[ Farklı IP'ler ]")
    for ip in ["172.16.0.1", "172.16.0.2", "172.16.0.3"]:
        print(f"  {ip}: {limiter.check(ip)}")

    print()
    print(limiter.stats())