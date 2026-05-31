# 🔐 Veri Yapıları II — Siber Güvenlik Odaklı Uygulamalar

> **Iğdır Üniversitesi** | Bilgisayar Mühendisliği Bölümü  
> Veri Yapıları II Final Projesi — 2025–2026 Bahar Dönemi  
> **Öğrenci:** Bedirhan ATABAY (2301050037)  
> **Öğretim Üyesi:** Prof. Dr. İhsan Ömür BUCAK

---

## 📋 İçindekiler

- [Proje Hakkında](#-proje-hakkında)
- [Modüller](#-modüller)
  - [Modül 1 — Hash Tablosu: Rate Limiting](#modül-1--hash-tablosu--rate-limiting)
  - [Modül 2 — TST: Zararlı Domain Tespiti](#modül-2--tst--zararlı-domain-tespiti)
  - [Modül 3 — KMP: Log Dosyası Tarama](#modül-3--kmp--log-dosyası-tarama)
  - [Modül 4 — Huffman: VPN Sıkıştırma](#modül-4--huffman--vpn-sıkıştırma)
  - [Modül 5 — Aho-Corasick: IDS Paket Tarama](#modül-5--aho-corasick--ids-paket-tarama)
- [Kurulum](#-kurulum)
- [Çalıştırma](#-çalıştırma)
- [Karmaşıklık Özeti](#-karmaşıklık-özeti)
- [Proje Yapısı](#-proje-yapısı)
- [Kaynakça](#-kaynakça)

---

## 🛡️ Proje Hakkında

Bu proje, **Veri Yapıları II** dersi kapsamında 5 farklı veri yapısının gerçek dünya **siber güvenlik problemlerine** uygulanmasını içermektedir. Her modül bağımsız çalışan bir Python scripti olup kendi test senaryosunu barındırmaktadır.

### Savunma Derinliği Mimarisi

┌─────────────────────────────────────────────────────┐
│                    SALDIRGAN                        │
└──────────────────────┬──────────────────────────────┘
│
┌────────────▼────────────┐
│   Modül 1 — Hash        │  ← Brute-force engelle
│   Rate Limiting         │
└────────────┬────────────┘
│
┌────────────▼────────────┐
│   Modül 2 — TST         │  ← Zararlı domain kes
│   DNS Threat Intel      │
└────────────┬────────────┘
│
┌────────────▼────────────┐
│   Modül 5 — Aho-Corasick│  ← Paketi tara
│   IDS/IPS               │
└────────────┬────────────┘
│
┌────────────▼────────────┐
│   Modül 4 — Huffman     │  ← Veriyi sıkıştır
│   VPN Sıkıştırma        │
└────────────┬────────────┘
│
┌────────────▼────────────┐
│   Modül 3 — KMP         │  ← Logları analiz et
│   SOC Log Tarama        │
└─────────────────────────┘


---

## 📦 Modüller

---

### Modül 1 — Hash Tablosu : Rate Limiting

**Problem:** Finans uygulamasına yönelik brute-force saldırılarını gerçek zamanlı engelleme.

**Senaryo:** Günlük 20 milyon giriş denemesi, %3'ü şüpheli IP. Her IP için sliding window sayacı tutularak 60 saniyede 10'dan fazla deneme yapan IP'ler otomatik bloklanıyor.

**Neden Hash Tablosu?**
- IP → sayaç eşlemesi için O(1) ortalama erişim
- BST'nin O(log n) gecikmesi saniyede yüz binlerce istekte birikir
- Open addressing ile bellek lokalitesi korunur

```python
# Örnek kullanım
limiter = RateLimiter()
result = limiter.check("10.0.0.99")
# BLOCKED (brute-force: 11 deneme)
```

| İşlem | Ort. | En Kötü |
|-------|------|---------|
| IP Kontrolü | O(1) | O(n) |
| Sayaç Güncelleme | O(1) | O(n) |
| Blok Kaldırma | O(1) | O(n) |
| Rehash | O(n) | O(n) |

> ⚠️ **Zayıf Nokta:** Dağıtık saldırılarda (binlerce farklı IP) eşik aşılmaz. Global sayaç + IP bloklist kombinasyonu gerekir.

---

### Modül 2 — TST : Zararlı Domain Tespiti

**Problem:** Kurumsal güvenlik duvarında 800.000 zararlı domain'i DNS sorgusunda 5ms altında kontrol etme.

**Senaryo:** Tehdit istihbarat veritabanı phishing, malware C2 ve botnet domainleri içeriyor. `evil.com` eklenince `sub.evil.com` da otomatik yakalanmalı (wildcard).

**Neden TST?**
- Trie'ın bellek sorununu çözer; her düğüm 3 çocuk (Trie'da 37+)
- Domain'leri ters çevirerek (com.evil.sub) sonek araması önek aramasına dönüşür
- Hash tablosu wildcard desteklemez, BST her karakter için O(log n)

```python
# Örnek kullanım
tst = ThreatIntelTST()
tst.add_threat("evil.com", "PHISHING")

is_bad, threat = tst.check_domain("login.evil.com")
# True, "PHISHING"  ← wildcard çalışıyor
```

| İşlem | Ort. | En Kötü |
|-------|------|---------|
| Ekleme | O(k) | O(k log n) |
| Tehdit Sorgusu | O(k) | O(k log n) |
| Bellek (Trie) | — | O(Σ·n) |
| Bellek (TST) | — | O(n) |

> ⚠️ **Zayıf Nokta:** Unicode punycode (xn-- öneki) ayrıca ele alınmazsa homograph saldırıları atlatılabilir.

---

### Modül 3 — KMP : Log Dosyası Tarama

**Problem:** SOC ekibinin sunucu loglarında SQL injection, XSS, path traversal gibi saldırı imzalarını araması.

**Senaryo:** Ortalama 500.000 satır, ~50 MB log dosyası. 50 farklı saldırı imzası, 30 saniye içinde taranmalı. Naif yöntem O(n·m) ile bu süreyi aşıyor.

**Neden KMP?**
- Failure fonksiyonu sayesinde metin üzerinde asla geri sarılmaz → O(n)
- Boyer-Moore Türkçe karakterlerde büyük alfabe yük getirir
- Rabin-Karp hash çakışması güvenlik analizinde yanlış negatif riski taşır

```python
# Örnek kullanım
alerts = scan_log_file(log_lines, signatures=[
    "UNION SELECT",
    "../../../etc/passwd",
    "<script>",
    "cmd.exe /c"
])
# Satır 47: [UNION SELECT] → GET /search?q=1' UNION SELECT...
```

| İşlem | Ort. | En Kötü |
|-------|------|---------|
| Failure Fonk. | O(m) | O(m) |
| Tek Satır Arama | O(n) | O(n) |
| Toplam (k imza) | O(k·(n+m)) | O(k·(n+m)) |
| Bellek | O(m) | O(m) |

> ⚠️ **Zayıf Nokta:** URL-encoding (%2F → /) normalizasyonu yapılmazsa imza kaçabilir. Base64 obfuscation'a karşı KMP yetersiz.

---

### Modül 4 — Huffman : VPN Trafik Sıkıştırma

**Problem:** VPN uygulamasında şifrelemeden önce payload sıkıştırma; bant genişliğini azaltma.

**Senaryo:** Ortalama payload 8 KB, günlük 5 milyon aktarım. Sıkıştırma + açma 2 ms altında bitmeli. HTTP/HTTPS ve JSON içeriği için %40-60 sıkıştırma oranı hedefleniyor.

**Neden Huffman?**
- Metin tabanlı veri için üstün sıkıştırma oranı
- LZ4 CRIME/BREACH side-channel saldırısına karşı savunmasız
- Açma işlemi basit: bit okuma + ağaç traversal → O(n)

```python
# Örnek kullanım
tree, table, encoded, enc_time, orig, comp, ratio = vpn_compress(payload)
# Sıkıştırma oranı: %45.9
# Sıkıştırma süresi: 29.08 ms
# Doğrulama: BAŞARILI ✓
```

| İşlem | Ort. | En Kötü |
|-------|------|---------|
| Frekans Hesabı | O(n) | O(n) |
| Ağaç İnşası | O(k log k) | O(k log k) |
| Kodlama | O(n) | O(n) |
| Açma | O(n) | O(n) |

> ⚠️ **Zayıf Nokta:** Ağaç alıcıya da gönderilmeli (+200-400 byte). Çok küçük payloadlarda ek yük oranı artar.

---

### Modül 5 — Aho-Corasick : IDS Paket Tarama

**Problem:** 10 Gbps ağda saniyede ~1 milyon paketi 2.000 exploit imzasına karşı gerçek zamanlı tarama.

**Senaryo:** KMP ile 2.000 imzayı sıralı çalıştırmak O(2000 × n) → latency bütçesini aşar. Tek geçişte tüm imzalar bulunmalı.

**Neden Aho-Corasick?**
- Tüm imzaları tek Trie'da birleştirir, failure linkleri ile otomata kurar
- Paket üzerinde tek geçiş: O(n + Sm + z)
- Rabin-Karp hash çakışması IDS'te sıfır tolerans

```python
# Örnek kullanım
ids = AhoCorasick()
for sig in exploit_signatures:
    ids.add_pattern(sig)
ids.build()

threats = ids.inspect_packet("GET /search?q=1' UNION SELECT username FROM users")
# [(19, 'UNION SELECT'), (26, 'SELECT')]
```

| İşlem | Ort. | En Kötü |
|-------|------|---------|
| Otomata İnşası | O(Sm) | O(Sm) |
| Failure Linkleri | O(Sm) | O(Sm) |
| Paket Tarama | O(n+z) | O(n+z) |
| Bellek | O(Sm·ALF) | O(Sm·ALF) |

> ⚠️ **Zayıf Nokta:** İmza güncellemesinde otomata baştan inşa edilmeli. Çift tampon stratejisi ile kesintisiz çalışma sağlanabilir.

---

## ⚙️ Kurulum

```bash
# Repoyu klonla
git clone https://github.com/kullanici-adi/veri-yapilari-2.git
cd veri-yapilari-2

# Python sürümünü kontrol et (3.8+ gerekli)
python --version

# Harici bağımlılık yok — yalnızca standart kütüphane kullanılmıştır
```

---

## ▶️ Çalıştırma

```bash
# Modül 1 — Rate Limiting
python modul1_hash_rate_limit.py

# Modül 2 — Zararlı Domain Tespiti
python modul2_tst_domain.py

# Modül 3 — Log Tarama
python modul3_kmp_log.py

# Modül 4 — VPN Sıkıştırma
python modul4_huffman_vpn.py

# Modül 5 — IDS Paket Tarama
python modul5_aho_corasick_ids.py
```

---

## 📊 Karmaşıklık Özeti

| Modül | Veri Yapısı | Problem | Karmaşıklık | Alternatif | Neden Elendi |
|-------|-------------|---------|-------------|------------|--------------|
| 1 | Hash Tablosu | Rate Limiting | O(1) ort. | BST | O(log n) birikir |
| 2 | TST | Domain Tespiti | O(k + log n) | Trie | Bellek sorunu |
| 3 | KMP | Log Tarama | O(n + m) | Boyer-Moore | Büyük alfabe yükü |
| 4 | Huffman | VPN Sıkıştırma | O(n + k log k) | LZ4 | CRIME saldırısı riski |
| 5 | Aho-Corasick | IDS Tarama | O(n + Sm + z) | Rabin-Karp | Hash çakışma riski |

---

## 📁 Proje Yapısı

veri-yapilari-2/
│ ├──kod
│ └── modul1_hash_rate_limit.py
│ └── modul2_tst_domain.py
│ └── modul3_kmp_log.py
│ └── modul4_huffman_vpn.py
│ └── modul5_aho_corasick_ids.py
│
├── rapor/
│   └── VeriYapilari2_SiberGuvenlik_Raporu.docx
│
└── README.md


---

## 📚 Kaynakça

- Cormen et al. (2009). *Introduction to Algorithms* (3rd ed.). MIT Press.
- Sedgewick & Wayne (2011). *Algorithms* (4th ed.). Addison-Wesley.
- Knuth, Morris & Pratt (1977). Fast pattern matching in strings. *SIAM Journal on Computing*.
- Aho & Corasick (1975). Efficient string matching. *Communications of the ACM*.
- Huffman (1952). A method for the construction of minimum-redundancy codes. *Proceedings of the IRE*.
- Stallings (2017). *Cryptography and Network Security* (7th ed.). Pearson.
- GeeksforGeeks — [Aho-Corasick Algorithm](https://www.geeksforgeeks.org/aho-corasick-algorithm-pattern-searching/)
- Stack Overflow — [djb2 Hash Function](https://stackoverflow.com/questions/10696223/reason-for-5381-number-in-djb2-hash-function)
- OWASP Foundation — [OWASP Top Ten](https://owasp.org/www-project-top-ten/)

---

<div align="center">

**Iğdır Üniversitesi — Bilgisayar Mühendisliği**  
Veri Yapıları II | 2025–2026 Bahar  
Nihat BAYRAM • 2201050011

</div>
