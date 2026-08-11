# Python SIEM — Firewall Log Korelasyon Motoru

Firewall cihazlarından syslog (UDP/514) ile gelen logları gerçek zamanlı toplayan, normalize eden ve MITRE ATT&CK tekniklerine dayalı korelasyon kurallarıyla saldırı tespiti yapan bir sistem. Sıfırdan Python ile yazıldı; hazır bir SIEM kütüphanesi kullanılmadı.

Amaç, bir SIEM'in arka planda gerçekte nasıl çalıştığını — log toplama, normalizasyon, durum (state) yönetimi, zaman pencereli korelasyon ve kural kalibrasyonu — uygulamalı olarak öğrenmekti.

---

## Mimari

```
Firewall (Syslog / UDP 514)
        │
        ▼
┌──────────────────────┐
│  dinleyici_thread    │  recvfrom() → kuyruğa at
│  (sadece yakalar)    │  Yavaş işlem YOK, bloklanmamalı
└──────────┬───────────┘
           ▼
     ┌───────────┐
     │  Kuyruk   │  queue.Queue(maxsize=10000)
     │           │  Veri kaybını önler
     └─────┬─────┘
           ▼
┌──────────────────────────────────────┐
│         isleyici_thread              │
│                                      │
│  1. Normalizasyon                    │
│     ham syslog → yapılandırılmış JSON│
│                                      │
│  2. Kalıcı kayıt                     │
│     → siem_loglari.jsonl             │
│                                      │
│  3. Korelasyon kuralları (4 adet)    │
│     ├─ Gürültü filtresi              │
│     ├─ Zaman pencereli state         │
│     ├─ Eşik kontrolü                 │
│     └─ Cooldown kontrolü             │
│                                      │
│  4. Alarm kaydı                      │
│     → alarmlar.jsonl                 │
└──────────────────────────────────────┘
```

**Neden iki ayrı thread?** UDP'de kernel buffer'ı dolarsa paketler *sessizce* düşer. Dinleme ve işleme aynı thread'de olsaydı, her dosya yazma işlemi sırasında gelen paketler kaybolabilirdi. Producer-consumer deseni bunu çözer: dinleyici sadece yakalar, ağır iş kuyruğun diğer tarafında yapılır.

---

## Dosya Yapısı

| Dosya | Sorumluluk |
|---|---|
| `main.py` | Socket, kuyruk, thread orkestrasyonu |
| `ayarlar.py` | Tüm eşikler, pencereler, allowlist — tek noktada |
| `normalizasyon.py` | Ham syslog → standart JSON şema |
| `korelasyon_ortak.py` | Kuralların paylaştığı yardımcılar (pencere temizleme, gürültü filtresi, cooldown) |
| `kural_port_tarama.py` | T1595 tespit mantığı |
| `kural_bruteforce.py` | T1110 tespit mantığı |
| `kural_dos.py` | T1498 tespit mantığı (tek kaynak) |
| `kural_ddos.py` | T1498 tespit mantığı (çok kaynaklı) |
| `io_yardimci.py` | JSON dönüşümü ve dosya yazma arayüzü |
| `test_senaryolari.py` | 6 senaryolu otomatik test scripti |

Yeni bir kural eklemek için: kural dosyasını yaz, `ayarlar.py`'a eşiği ekle, `main.py`'daki `AKTIF_KURALLAR` listesine fonksiyonu ekle. İşleyici döngüsüne dokunmaya gerek yok.

---

## Uygulanan MITRE ATT&CK Teknikleri

| Teknik | Taktik | Gruplama Anahtarı | Sayılan | Mantık |
|---|---|---|---|---|
| **T1595** Active Scanning | Reconnaissance | `src_ip` | Benzersiz `dst_port` | Bir kaynak, çok sayıda **farklı porta** deniyor |
| **T1110** Brute Force | Credential Access | `(src_ip, dst_ip, dst_port)` | Toplam tekrar | Aynı hedefe **ısrarlı tekrar** |
| **T1498** DoS (tek kaynak) | Impact | `(src_ip, dst_ip)` | Toplam istek | Tek kaynaktan **hacim** saldırısı |
| **T1498** DDoS (çok kaynaklı) | Impact | `dst_ip` | Benzersiz `src_ip` | Bir hedefe **çok kaynaktan** yoğunluk |

Dikkat çekici nokta: T1595 ile DDoS kuralları **ayna simetri** — biri `src_ip` bazında port sayar, diğeri `dst_ip` bazında kaynak sayar. Aynı algoritma iskeleti, rolleri ters çevrilmiş hali.

Tüm kurallar ortak bir iskelet kullanır:

```
1. Zaman penceresi dışındaki kayıtları temizle  (kayan pencere)
2. Yeni olayı state'e ekle
3. Say (set ile benzersiz, veya len ile toplam)
4. Eşiği aştıysa → cooldown kontrolü → alarm
```

---

## Karşılaşılan Problemler ve Çözümleri

Bu bölüm projenin en öğretici kısmı. Kuralları yazmak kolaydı; onları gerçek trafikte **doğru çalışır hale getirmek** asıl işti.

### 1. Broadcast ve multicast gürültüsü

**Belirti:** Brute Force kuralı sürekli tetikleniyordu — `192.168.x.255` (IPv4 broadcast) ve `ff02::fb` (IPv6 multicast, mDNS) hedeflerine.

**Kök neden:** Bu adresler doğası gereği tekrarlayan trafik alır — mDNS, SSDP, NetBIOS gibi ağ keşif protokolleri sürekli çalışır. Kural "aynı hedefe tekrar tekrar istek" arıyordu, broadcast zaten tanımı gereği bunu yapar.

**Çözüm:** `ipaddress` kütüphanesiyle `hedef_gurultu_mu()` filtresi. Multicast, link-local ve broadcast adresleri kural değerlendirmesine hiç sokulmuyor.

```python
if adres.is_multicast or adres.is_link_local:
    return True   # gürültü, yoksay
```

### 2. Meşru yüksek hacimli trafik (DNS)

**Belirti:** `8.8.8.8:53` hedefine giden normal DNS trafiği DoS alarmı üretiyordu — 5 saniyede 30+ istek.

**Kök neden:** Eşik değeri sentetik test verisine göre seçilmişti. Gerçekte tek bir web sayfası açılışı onlarca DNS sorgusu üretir (her subdomain, her CDN, her reklam ağı ayrı sorgu; ayrıca IPv4/IPv6 için ikişer kayıt). Normal kullanım eşiği rahatça aşıyordu.

**Çözüm:** İki katmanlı:
- Eşik gerçekçi seviyeye çekildi (30 → 200)
- `GUVENILIR_HEDEFLER` allowlist'i eklendi (bilinen DNS sunucuları kural dışı)

### 3. Alarm spam'i

**Belirti:** Eşik aşıldıktan sonra **her yeni olay** ayrı bir alarm satırı üretiyordu. Tek bir DoS olayı 100+ alarm kaydı oluşturuyordu (`toplam_istek: 31, 32, 33, 34...`).

**Kök neden:** Kural, her çağrıldığında eşiği kontrol ediyor ve aşılmışsa alarm basıyordu — "bu şey için zaten alarm verdim mi" diye bakmıyordu.

**Çözüm:** `alarm_verilebilir_mi()` cooldown mekanizması. Her kural+anahtar kombinasyonu için son alarm zamanı tutulur; 5 dakika içinde aynı şey için tekrar alarm basılmaz.

**Ölçülen etki:** Test ortamında toplam alarm sayısı **33 → 4**. Her gerçek olay için tam olarak bir alarm.

### 4. Sessiz hata: yanlış değişken referansı

**Belirti:** DoS kuralı tetikleniyordu (ekranda görünüyordu) ama alarm dosyasında yoktu — bunun yerine önceki Brute Force kaydı tekrar yazılıyordu.

**Kök neden:** Kopyala-yapıştır hatası. DoS bloğunda `dos_alarm_satiri` yerine `bf_alarm_satiri` yazılmıştı:

```python
dos_alarm_satiri = json.dumps(dos_alarm_detay, ...)
print("!!! ALARM !!!", dos_alarm_satiri)      # doğru
alarm_dosyasi.write(bf_alarm_satiri + "\n")   # HATA — önceki kuralın verisi
```

Python'da sözdizimsel olarak geçerli olduğu için hiçbir hata mesajı üretmiyordu. Program sessizce yanlış çalışıyordu.

**Çözüm — semptomu değil, nedeni:** Hatayı düzeltmek yetmezdi; aynı kalıbın 4 kez kopyalanmış olması kök nedendi. `io_yardimci.py` modülü yazıldı, JSON/print/write/flush tek fonksiyonda toplandı. Kurallar bir listeye alınıp döngüyle çalıştırılır hale getirildi:

```python
for kural_fonksiyonu in AKTIF_KURALLAR:
    alarm_kontrol_ve_yaz(kural_fonksiyonu, normalized, alarm_dosyasi)
```

Artık kopyalanacak bir blok olmadığı için bu hata yapısal olarak imkansız.

### 5. Zamanlama hassasiyeti (yük testi sırasında)

Saniyede 500 mesaj hedeflenen testte gerçekleşen hız 411 msg/s ölçüldü. Sebep: Windows'un zamanlayıcı çözünürlüğü (~15.6 ms), `time.sleep()` ile milisaniye altı hassasiyette zamanlamayı garanti etmiyor. Test aracının sınırı olarak kabul edildi.

---

## Sınırlamalar

Dürüst olmak gerekirse bu sistem bir üretim SIEM'i değil. Bilinen sınırları:

**Tespit sınırları**
- **Yavaş tarama (slow scan) yakalanmaz.** Port taraması kuralı 1 saniyelik pencere kullanır. Bir saldırgan port denemeleri arasında 10 saniye beklerse, her yeni olayda önceki kayıtlar pencereden düşer ve sayaç asla eşiği geçmez. Gerçek testte doğrulandı: nmap yakalanıyor, elle tek tek yapılan tarama yakalanmıyor. Çözümü birden fazla paralel zaman penceresi olurdu (örn. hem "1sn/5 port" hem "1sa/50 port").
- **Sadece ağ katmanı görünürlüğü var.** Firewall logu, bir makinede çalışan zararlı süreci, PowerShell komutunu veya registry değişikliğini göremez. Gerçek tespitlerin çoğu endpoint (EDR/Sysmon) verisi gerektirir.
- **Tehdit istihbaratı yok.** "Bu IP bilinen bir C2 sunucusu mu" sorusuna cevap veremiyor.
- **Bağlam zenginleştirme yok.** "Bu kullanıcı normalde Türkiye'den bağlanır, şimdi başka ülkeden" gibi davranışsal analiz yapılmıyor.

**Teknik sınırlar**
- **Ölçeklenmez.** Tek process, tek işleyici thread, RAM içi state. Birkaç yüz EPS'e kadar sorunsuz; 10.000 EPS gibi kurumsal yüklerde çöker. Gerçek sistemler Kafka + dağıtık işleme kullanır.
- **State kalıcı değil.** Program yeniden başladığında tüm sayaçlar sıfırlanır. Devam eden bir saldırı, restart anında görünmez hale gelir.
- **UDP paket kaybı tam çözülmedi.** Kuyruk ve büyütülmüş kernel buffer riski azaltır ama ortadan kaldırmaz. TCP syslog veya disk tabanlı spool (rsyslog'un yaptığı gibi) gerekirdi.
- **Tek log kaynağı formatı.** Parser Fortinet'in key=value formatına göre yazıldı. Başka bir vendor için yeniden yazılması gerekir.

---

## Kurulum ve Çalıştırma

```bash
# Dinleyiciyi başlat (yönetici yetkisi gerekebilir — port 514)
python main.py

# Ayrı bir terminalde test senaryolarını çalıştır
python test_senaryolari.py
```

Çıktılar:
- `siem_loglari.jsonl` — tüm normalize edilmiş loglar
- `alarmlar.jsonl` — tetiklenen alarmlar

Eşikleri ayarlamak için `ayarlar.py` dosyasını düzenlemek yeterli.

---

## Test

`test_senaryolari.py` 6 senaryo içerir — 4 pozitif (alarm beklenen), 2 negatif (alarm beklenmeyen):

| Senaryo | İçerik | Beklenen |
|---|---|---|
| 0 | Normal trafik | Alarm yok |
| 1 | 8 farklı porta hızlı deny | T1595 |
| 2 | Aynı porta 15 kez deny | T1110 |
| 3 | Aynı hedefe 250 istek | T1498 (tek kaynak) |
| 4 | 25 farklı kaynaktan aynı hedefe | T1498 (çok kaynaklı) |
| 5 | Broadcast adresine 20 farklı port | Alarm yok (filtre testi) |

Negatif senaryolar, yanlış pozitif düzeltmelerinin regresyona uğramadığını doğrular.

---

## Geliştirilebilecek Yönler

- Sigma kural formatına geçiş (vendor-bağımsız tespit dili)
- Endpoint log kaynakları (Sysmon, Windows Event Log)
- Threat Intelligence entegrasyonu (AbuseIPDB, OTX)
- Kalıcı state (Redis / disk tabanlı)
- Alarm severity derecelendirmesi ve raporlama arayüzü
- Periyodiklik tabanlı tespit (T1071 — C2 Beaconing)
- Çoklu zaman penceresi (yavaş tarama problemi için)

---

## Öğrenilenler

Bu proje boyunca kod yazmaktan çok, **kuralları gerçek trafikte doğru çalışır hale getirmek** zaman aldı. Bir tespit kuralının mantığını yazmak yarım saat sürüyor; onu yanlış pozitif üretmeyecek şekilde kalibre etmek günler alabiliyor. Gerçek SOC işinin ağırlığının neden "tuning" tarafında olduğunu bu şekilde deneyimlemiş oldum.
