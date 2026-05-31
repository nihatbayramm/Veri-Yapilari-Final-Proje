import heapq
import time
from collections import Counter

class HuffNode:
    def __init__(self, byte_val, freq):
        self.byte_val = byte_val
        self.freq = freq
        self.left = self.right = None

    def __lt__(self, other):
        return self.freq < other.freq

def build_huffman_tree(data: bytes):
    freq = Counter(data)
    heap = [HuffNode(b, f) for b, f in freq.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        parent = HuffNode(None, left.freq + right.freq)
        parent.left = left
        parent.right = right
        heapq.heappush(heap, parent)

    return heap[0] if heap else None

def generate_codes(node, prefix="", table=None):
    if table is None:
        table = {}
    if node is None:
        return table
    if node.byte_val is not None:
        table[node.byte_val] = prefix or "0"
    else:
        generate_codes(node.left,  prefix + "0", table)
        generate_codes(node.right, prefix + "1", table)
    return table

def encode(data: bytes, table: dict) -> str:
    return ''.join(table[b] for b in data)

def decode(bit_string: str, root) -> bytes:
    result = []
    node = root
    for bit in bit_string:
        node = node.left if bit == '0' else node.right
        if node.byte_val is not None:
            result.append(node.byte_val)
            node = root
    return bytes(result)

def vpn_compress(payload: bytes):
    t0 = time.perf_counter()
    tree = build_huffman_tree(payload)
    table = generate_codes(tree)
    encoded = encode(payload, table)
    elapsed = (time.perf_counter() - t0) * 1000

    original_bits = len(payload) * 8
    compressed_bits = len(encoded)
    ratio = (1 - compressed_bits / original_bits) * 100

    return tree, table, encoded, elapsed, original_bits, compressed_bits, ratio

def vpn_decompress(encoded: str, tree) -> tuple:
    t0 = time.perf_counter()
    decoded = decode(encoded, tree)
    elapsed = (time.perf_counter() - t0) * 1000
    return decoded, elapsed


# ─── TEST ───
if __name__ == "__main__":
    print("=== Huffman VPN Sıkıştırma Testi ===\n")

    # Gerçekçi JSON payload simülasyonu
    sample = ('{"user":"admin","token":"eyJhbGciOiJIUzI1NiJ9",'
              '"data":{"items":[{"id":1,"name":"laptop","price":1200},'
              '{"id":2,"name":"mouse","price":25}]},'
              '"status":"ok","timestamp":"2026-06-01T10:00:00Z"}') * 30
    payload = sample.encode('utf-8')

    print(f"Girdi: {len(payload):,} karakter ({len(payload):,} bayt)")
    print(f"Benzersiz byte sayısı: {len(set(payload))}")

    tree, table, encoded, enc_time, orig_bits, comp_bits, ratio = vpn_compress(payload)

    print(f"Sıkıştırma süresi: {enc_time:.2f} ms\n")
    print(f"Orijinal bit sayısı  : {orig_bits:,}")
    print(f"Sıkıştırılmış bit    : {comp_bits:,}")
    print(f"Sıkıştırma oranı     : %{ratio:.1f}\n")

    decoded, dec_time = vpn_decompress(encoded, tree)
    ok = decoded == payload
    print(f"Açma süresi: {dec_time:.2f} ms")
    print(f"Doğrulama: {'BAŞARILI ✓' if ok else 'HATA ✗'}\n")

    print("Karakter kod tablosu (en sık 8):")
    sorted_table = sorted(table.items(), key=lambda x: len(x[1]))[:8]
    for byte_val, code in sorted_table:
        char = chr(byte_val) if 32 <= byte_val < 127 else f"\\x{byte_val:02x}"
        freq = payload.count(byte_val)
        print(f"  '{char}'  -> {code:<10} (frekans: {freq:,})")