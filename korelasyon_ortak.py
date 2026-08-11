"""
Tum korelasyon kurallarinin (port taramasi, brute force, ileride eklenecek
digerleri) ORTAK olarak kullandigi yardimci fonksiyonlar burada.

Suan icin tek ortak islem: bir kayit listesinden, zaman penceresi disina
dusmus (eski) kayitlari atmak. Hem port taramasi hem brute force, farkli
seyler saklasa da (biri (zaman,port) tutuyor, digeri sadece zaman),
her ikisinde de "ilk eleman zaman damgasi" kuralina uyuyoruz - bu sayede
tek bir fonksiyon ikisine de hizmet edebiliyor.
"""

import ipaddress
import time
from collections import defaultdict


# Her kural+anahtar kombinasyonu icin, en son ne zaman alarm verdigimizi tutar
_son_alarm_zamanlari = defaultdict(float)


def alarm_verilebilir_mi(kural_adi, anahtar, cooldown_suresi):
    """
    Ayni sey icin tekrar tekrar alarm basmayi engeller (cooldown / soguma suresi).

    Neden gerekli: esik asildiktan sonra GELEN HER YENI OLAY icin alarm
    basarsak, tek bir olay yuzlerce alarm satiri uretir. Gercek bir SOC
    ekibi bunu okuyamaz. Bunun yerine: bir kez alarm ver, sonra belirli
    bir sure (cooldown) boyunca ayni sey icin sus.

    kural_adi:        hangi kural (orn. "dos") - farkli kurallar birbirini engellemesin
    anahtar:          neyi takip ediyoruz (orn. (src_ip, dst_ip) tuple'i)
    cooldown_suresi:  kac saniye boyunca ayni sey icin tekrar alarm basilmasin

    True donerse: alarm basilabilir (ve son alarm zamani guncellenir)
    False donerse: cooldown suresi dolmamis, alarm bastirilmali
    """
    kayit_anahtari = (kural_adi, anahtar)
    simdiki_zaman = time.time()

    son_alarm = _son_alarm_zamanlari[kayit_anahtari]

    if simdiki_zaman - son_alarm < cooldown_suresi:
        return False   # daha once alarm verdik, cooldown suresi henuz dolmadi

    _son_alarm_zamanlari[kayit_anahtari] = simdiki_zaman
    return True


def eskileri_temizle(kayit_listesi, simdiki_zaman, pencere_suresi):
    """
    kayit_listesi: [(zaman, ...ekstra_bilgi...), ...] ya da [zaman, zaman, ...]
                   -> her elemanin ilk parcasi (ya da elemanin kendisi) zaman olmali
    simdiki_zaman:  time.time() ile alinan su anki zaman
    pencere_suresi: kac saniye geriye kadar "gecerli" sayilacagi

    Donen deger: sadece pencere icinde kalan (guncel) kayitlarin listesi
    """
    guncel_liste = []

    for kayit in kayit_listesi:
        # Kayit bir tuple ise ((zaman, port) gibi) ilk elemanini al,
        # degilse (sadece zaman ise) kaydin kendisini zaman olarak kullan
        if isinstance(kayit, tuple):
            zaman_degeri = kayit[0]
        else:
            zaman_degeri = kayit

        yas = simdiki_zaman - zaman_degeri
        if yas <= pencere_suresi:
            guncel_liste.append(kayit)
        # yas pencereden buyukse: hicbir sey yapmiyoruz, kayit burada eleniyor

    return guncel_liste


def hedef_gurultu_mu(ip_str):
    """
    Bir IP adresinin BROADCAST ya da MULTICAST oldugunu kontrol eder.

    Neden gerekli: bu tur adresler dogasi geregi TEKRARLAYICI trafik alir
    (ag kesfi, mDNS, SSDP, NetBIOS gibi normal "gurultu"). Brute force ya da
    DoS gibi kurallarimiz "ayni hedefe tekrar tekrar istek" ariyor, ama
    broadcast/multicast zaten her zaman tekrar eder - bu yuzden bunlari
    kural disi birakmazsak surekli yanlis alarm (false positive) uretiriz.

    Ornekler:
      192.168.1.255   -> IPv4 broadcast (yaygin /24 agda son oktet 255)
      ff02::fb        -> IPv6 multicast (mDNS kesif adresi)
      224.0.0.251     -> IPv4 multicast (mDNS)

    True donerse: bu IP'yi yoksay, kurala hic sokma
    False donerse: normal bir hedef, kurala devam et
    """
    if not ip_str:
        return False

    try:
        adres = ipaddress.ip_address(ip_str)
    except ValueError:
        # Gecerli bir IP formatinda degilse (parse hatasi vs.), yoksaymiyoruz -
        # kural kendi mantigiyla degerlendirsin, burada karar vermeyelim
        return False

    if adres.is_multicast:
        return True

    if adres.is_link_local:
        # fe80::... (IPv6) turu adresler - yerel ag kesfi icin kullanilir, gurultu
        return True

    # IPv4 icin yaygin broadcast heuristigi: son oktet 255
    # (Tam dogrusu subnet maskesine bakmak olurdu ama bu bilgi elimizde yok,
    #  /24 aglarda en yaygin durum bu oldugu icin pratik bir kisayol kullaniyoruz)
    if isinstance(adres, ipaddress.IPv4Address) and str(adres).endswith(".255"):
        return True

    return False