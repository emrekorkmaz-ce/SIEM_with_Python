"""
MITRE T1498 - Network Denial of Service (cok kaynakli / DDoS versiyonu).

Onceki (tek kaynak) DoS kuralindan farki: burada gruplama anahtari
src_ip DEGIL, dst_ip - yani "hangi HEDEF, kac FARKLI kaynaktan bombalaniyor"
sorusuna cevap ariyoruz. Bu, port taramasi kuraliyla ayna simetri:

  Port Tarama : anahtar=src_ip,  sayilan=BENZERSIZ port  (set)
  DDoS        : anahtar=dst_ip,  sayilan=BENZERSIZ src_ip (set)

Ikisi de "farklilik" olcuyor, sadece hangi alanin anahtar/sayilan oldugu
yer degistirmis durumda.
"""

import time
from collections import defaultdict

from ayarlar import DDOS_PENCERE_SURESI, DDOS_ESIK, COOLDOWN_SURESI, GUVENILIR_HEDEFLER
from korelasyon_ortak import eskileri_temizle, hedef_gurultu_mu, alarm_verilebilir_mi

# Bu kuralin kendi state'i - her dst_ip icin, (zaman, src_ip) kayitlarinin listesi
ddos_state = defaultdict(list)


def ddos_kontrol_et(normalized):
    src_ip = normalized.get("src_ip")
    dst_ip = normalized.get("dst_ip")

    # Dikkat: burada da 'action' kontrolu YOK - hem allow hem deny sayiliyor,
    # cunku DDoS trafiginin bir kismi henuz reddedilmemis olabilir
    if not src_ip or not dst_ip:
        return False, None

    # Hedef broadcast/multicast ise (dogasi geregi cok kaynaktan trafik alir,
    # bu normal) yoksay - false positive'i onceden engelliyoruz
    if hedef_gurultu_mu(dst_ip):
        return False, None

    # Bilinen mesru yogun hedefleri yoksay
    if dst_ip in GUVENILIR_HEDEFLER:
        return False, None

    simdiki_zaman = time.time()

    # --- ADIM 1: Eski kayitlari temizle (ORTAK fonksiyon) ---
    ddos_state[dst_ip] = eskileri_temizle(
        ddos_state[dst_ip], simdiki_zaman, DDOS_PENCERE_SURESI
    )

    # --- ADIM 2: Yeni kaydi ekle - (zaman, KAYNAK ip) ---
    ddos_state[dst_ip].append((simdiki_zaman, src_ip))

    # --- ADIM 3: BENZERSIZ kaynak (src_ip) sayisini hesapla ---
    benzersiz_kaynaklar = set()
    for (kayit_zaman, kayit_src_ip) in ddos_state[dst_ip]:
        benzersiz_kaynaklar.add(kayit_src_ip)

    benzersiz_sayi = len(benzersiz_kaynaklar)

    # --- ADIM 4: Esik kontrolu ---
    if benzersiz_sayi > DDOS_ESIK:
        # Cooldown: ayni hedef icin son 5 dakikada alarm verdiysek tekrar basma
        if not alarm_verilebilir_mi("ddos", dst_ip, COOLDOWN_SURESI):
            return False, None

        detay = {
            "kural": "DDoS Supheli - Cok Kaynakli (MITRE T1498)",
            "dst_ip": dst_ip,
            "benzersiz_kaynak_sayisi": benzersiz_sayi,
            "ornek_kaynaklar": sorted(benzersiz_kaynaklar)[:10],  # hepsini degil, ilk 10'unu goster
            "pencere_suresi_sn": DDOS_PENCERE_SURESI,
        }
        return True, detay

    return False, None