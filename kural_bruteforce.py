"""
MITRE T1110 - Brute Force tespit kurali.
Ayni (src_ip, dst_ip, dst_port) uclusune, kisa surede COK SAYIDA
tekrar deneme (deny) gelirse alarm.
"""

import time
from collections import defaultdict

from ayarlar import BF_PENCERE_SURESI, BF_ESIK, COOLDOWN_SURESI
from korelasyon_ortak import eskileri_temizle, hedef_gurultu_mu, alarm_verilebilir_mi

# Bu kuralin kendi state'i - port taramasininkiyle karismaz
bruteforce_state = defaultdict(list)


def bruteforce_kontrol_et(normalized):
    src_ip = normalized.get("src_ip")
    dst_ip = normalized.get("dst_ip")
    dst_port = normalized.get("dst_port")
    action = normalized.get("action")

    if not src_ip or not dst_ip or not dst_port or not action:
        return False, None

    if action != "deny":
        return False, None

    # YENİ: Hedef broadcast/multicast ise (mDNS, SSDP, ag kesfi gibi normal
    # tekrarlayici trafik) bu kuralla hic ilgilenmiyoruz - saldiri degil
    if hedef_gurultu_mu(dst_ip):
        return False, None

    anahtar = (src_ip, dst_ip, dst_port)
    simdiki_zaman = time.time()

    # --- ADIM 1: Eski kayitlari temizle (ORTAK fonksiyonu kullaniyoruz) ---
    bruteforce_state[anahtar] = eskileri_temizle(
        bruteforce_state[anahtar], simdiki_zaman, BF_PENCERE_SURESI
    )

    # --- ADIM 2: Yeni denemeyi ekle ---
    bruteforce_state[anahtar].append(simdiki_zaman)

    # --- ADIM 3: TOPLAM deneme sayisi (bu kurala ozel kisim, set YOK) ---
    toplam_deneme = len(bruteforce_state[anahtar])

    # --- ADIM 4: Esik kontrolu ---
    if toplam_deneme > BF_ESIK:
        # Cooldown: ayni uclu icin son 5 dakikada alarm verdiysek tekrar basma
        if not alarm_verilebilir_mi("bruteforce", anahtar, COOLDOWN_SURESI):
            return False, None

        detay = {
            "kural": "Brute Force Supheli (MITRE T1110)",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "toplam_deneme_sayisi": toplam_deneme,
            "pencere_suresi_sn": BF_PENCERE_SURESI,
        }
        return True, detay

    return False, None