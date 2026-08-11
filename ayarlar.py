"""
Tum sabit ayarlar burada toplanir. Bir esigi degistirmek istedigimizde
tek bu dosyaya bakmamiz yeterli olsun diye - baska hicbir dosyada
sabit sayi (magic number) olmamali.
"""

# --- Socket / Kuyruk ayarlari ---
DINLEME_IP = "0.0.0.0"
DINLEME_PORT = 514
SOCKET_BUFFER_BOYUTU = 4 * 1024 * 1024   # 4 MB
KUYRUK_MAX_BOYUT = 10000

# --- COOLDOWN (alarm tekrarini onleme) ---
# Bir kural, ayni anahtar icin alarm verdikten sonra, bu sure boyunca
# ayni sey icin tekrar alarm basmaz. Alarm spam'ini onler.
COOLDOWN_SURESI = 300   # 5 dakika

# --- Port Taramasi (MITRE T1595) ayarlari ---
PT_PENCERE_SURESI = 1    # saniye
PT_ESIK = 5               # bu pencerede 5'ten fazla FARKLI porta deny alirsa alarm

# --- Brute Force (MITRE T1110) ayarlari ---
BF_PENCERE_SURESI = 10   # saniye
BF_ESIK = 10              # bu pencerede 10'dan fazla deneme olursa alarm

# --- DoS Gostergesi (MITRE T1498) ayarlari - tek kaynak versiyonu ---
# NOT: Gercek trafikle test edildi. 30 esigi cok dusuktu - normal DNS
# ve uygulama trafigi bile asiyordu. Gercekci bir seviyeye cekildi.
DOS_PENCERE_SURESI = 5    # saniye
DOS_ESIK = 200             # bu pencerede ayni (src,dst) ikilisine 200'den fazla istek gelirse alarm

# --- DDoS Gostergesi (MITRE T1498) ayarlari - cok kaynakli versiyon ---
DDOS_PENCERE_SURESI = 5    # saniye
DDOS_ESIK = 20              # bu pencerede ayni hedefe 20'den fazla FARKLI kaynaktan istek gelirse alarm

# --- ALLOWLIST: Bilinen/mesru yuksek hacimli hedefler ---
# Bu IP'ler DoS/DDoS kurallarinda yoksayilir. DNS sunuculari gibi
# dogasi geregi cok yogun trafik alan mesru servisler buraya eklenir.
GUVENILIR_HEDEFLER = {
    "8.8.8.8",        # Google DNS
    "8.8.4.4",        # Google DNS (ikincil)
    "1.1.1.1",        # Cloudflare DNS
    "1.0.0.1",        # Cloudflare DNS (ikincil)
    "208.67.222.222", # OpenDNS
    "208.67.220.220", # OpenDNS
}

# --- Dosya isimleri ---
LOG_DOSYASI = "siem_loglari.jsonl"
ALARM_DOSYASI = "alarmlar.jsonl"