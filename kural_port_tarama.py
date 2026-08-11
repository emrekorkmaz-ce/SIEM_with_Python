"""
MITRE T1595 - Active Scanning (Port Taramasi) tespit kurali.
Ayni src_ip'den, kisa surede, cok sayida FARKLI porta deny alinirsa alarm.
"""

import time
from collections import defaultdict

from ayarlar import PT_PENCERE_SURESI, PT_ESIK, COOLDOWN_SURESI
from korelasyon_ortak import eskileri_temizle, hedef_gurultu_mu, alarm_verilebilir_mi

# Bu kuralin kendi state'i - baska hicbir kural buna dokunmaz
port_tarama_state = defaultdict(list)


def port_taramasi_kontrol_et(normalized):
    src_ip = normalized.get("src_ip")
    dst_ip = normalized.get("dst_ip")
    dst_port = normalized.get("dst_port")
    action = normalized.get("action")

    if not src_ip or not dst_port or not action:
        return False, None

    if action != "deny":
        return False, None

    # YENİ: Hedef broadcast/multicast ise yoksay - port taramasi kuralinda
    # bu filtre eksikti, bruteforce/dos'ta vardi ama burada unutulmustu
    if hedef_gurultu_mu(dst_ip):
        return False, None

    simdiki_zaman = time.time()

    # --- ADIM 1: Eski kayitlari temizle (ORTAK fonksiyonu kullaniyoruz) ---
    port_tarama_state[src_ip] = eskileri_temizle(
        port_tarama_state[src_ip], simdiki_zaman, PT_PENCERE_SURESI
    )

    # --- ADIM 2: Yeni kaydi ekle ---
    port_tarama_state[src_ip].append((simdiki_zaman, dst_port))

    # --- ADIM 3: BENZERSIZ port sayisini hesapla (bu kurala ozel kisim) ---
    benzersiz_portlar = set()
    for (kayit_zaman, kayit_port) in port_tarama_state[src_ip]:
        benzersiz_portlar.add(kayit_port)

    benzersiz_sayi = len(benzersiz_portlar)

    # --- ADIM 4: Esik kontrolu ---
    if benzersiz_sayi > PT_ESIK:
        # Cooldown: ayni src_ip icin son 5 dakikada alarm verdiysek tekrar basma
        if not alarm_verilebilir_mi("port_tarama", src_ip, COOLDOWN_SURESI):
            return False, None

        detay = {
            "kural": "Port Taramasi Supheli (MITRE T1595)",
            "src_ip": src_ip,
            "benzersiz_port_sayisi": benzersiz_sayi,
            "denenen_portlar": sorted(benzersiz_portlar, key=lambda p: str(p)),
            "pencere_suresi_sn": PT_PENCERE_SURESI,
        }
        return True, detay

    return False, None