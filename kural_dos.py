"""
MITRE T1498 - Network Denial of Service (tek kaynak versiyonu).

Ayni (src_ip, dst_ip) ikilisine, kisa surede COK SAYIDA istek gelirse
alarm uretir. Brute force'tan farki: action filtresi YOK - hem allow
hem deny sayiliyor, cunku DoS trafiginin bir kismi firewall tarafindan
kabul edilmis (allow) bile olabilir.

GERCEK TRAFIK TESTINDEN SONRA EKLENENLER:
  - Allowlist: DNS sunuculari gibi mesru yogun hedefler yoksayiliyor
  - Cooldown: esik asildiktan sonra her istekte degil, 5 dakikada
    bir alarm basiliyor (alarm spam'ini onlemek icin)
"""

import time
from collections import defaultdict

from ayarlar import DOS_PENCERE_SURESI, DOS_ESIK, COOLDOWN_SURESI, GUVENILIR_HEDEFLER
from korelasyon_ortak import eskileri_temizle, hedef_gurultu_mu, alarm_verilebilir_mi

# Bu kuralin kendi state'i
dos_state = defaultdict(list)


def dos_kontrol_et(normalized):
    src_ip = normalized.get("src_ip")
    dst_ip = normalized.get("dst_ip")
    dst_port = normalized.get("dst_port")

    # Dikkat: burada 'action' kontrolu YOK - hem allow hem deny sayiliyor
    if not src_ip or not dst_ip:
        return False, None

    # Broadcast/multicast hedefleri yoksay
    if hedef_gurultu_mu(dst_ip):
        return False, None

    # YENI: Bilinen mesru yogun hedefleri (DNS sunuculari vs.) yoksay
    if dst_ip in GUVENILIR_HEDEFLER:
        return False, None

    anahtar = (src_ip, dst_ip)
    simdiki_zaman = time.time()

    # --- ADIM 1: Eski kayitlari temizle (ORTAK fonksiyon) ---
    dos_state[anahtar] = eskileri_temizle(
        dos_state[anahtar], simdiki_zaman, DOS_PENCERE_SURESI
    )

    # --- ADIM 2: Yeni istegi ekle ---
    dos_state[anahtar].append(simdiki_zaman)

    # --- ADIM 3: TOPLAM istek sayisi ---
    toplam_istek = len(dos_state[anahtar])

    # --- ADIM 4: Esik kontrolu ---
    if toplam_istek > DOS_ESIK:
        # YENI: Cooldown kontrolu - ayni (src,dst) icin son 5 dakikada
        # zaten alarm verdiysek, tekrar basma
        if not alarm_verilebilir_mi("dos", anahtar, COOLDOWN_SURESI):
            return False, None

        detay = {
            "kural": "DoS Supheli - Tek Kaynak (MITRE T1498)",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "denenen_port": dst_port,
            "toplam_istek_sayisi": toplam_istek,
            "pencere_suresi_sn": DOS_PENCERE_SURESI,
        }
        return True, detay

    return False, None