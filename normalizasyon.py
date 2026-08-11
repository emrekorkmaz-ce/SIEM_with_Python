"""
Ham (syslog/key-value formatinda) UDP verisini, bizim standart
sema/dictionary yapimiza cevirir. Sadece bu ise odaklanan dosya.
"""

import re


def pri_ayikla(ham_metin):
    eslesme = re.match(r"^<(\d+)>(.*)$", ham_metin)
    if eslesme:
        pri = int(eslesme.group(1))
        kalan = eslesme.group(2)
        return pri, kalan
    return None, ham_metin


def key_value_parse(metin):
    sonuc = {}
    for parca in metin.strip().split():
        if "=" in parca:
            anahtar, deger = parca.split("=", 1)
            deger = deger.strip('"')
            sonuc[anahtar] = deger
    return sonuc


def normalize_et(ham_bytes, kimden_geldi, alinma_zamani):
    ham_metin = ham_bytes.decode(errors="replace")

    pri, kalan_metin = pri_ayikla(ham_metin)
    alanlar = key_value_parse(kalan_metin)

    tarih = alanlar.get("date")
    saat = alanlar.get("time")

    normalized = {
        "pri": pri,
        "alinma_zamani": f"{tarih} {saat}",

        # Cihaz bilgileri
        "device_name": alanlar.get("devname"),
        "device_id": alanlar.get("devid"),
        "vdom": alanlar.get("vd"),

        # Olay bilgileri
        "event_type": alanlar.get("type"),
        "event_subtype": alanlar.get("subtype"),
        "severity": alanlar.get("level"),
        "action": alanlar.get("action"),
        "session_id": alanlar.get("sessionid"),

        # Kaynak
        "src_name": alanlar.get("srcname"),
        "src_ip": alanlar.get("srcip"),
        "src_port": alanlar.get("srcport"),
        "src_country": alanlar.get("srccountry"),

        # Hedef
        "dst_ip": alanlar.get("dstip"),
        "dst_port": alanlar.get("dstport"),
        "dst_country": alanlar.get("dstcountry"),

        # NAT bilgileri
        "nat_type": alanlar.get("trandisp"),
        "translated_ip": alanlar.get("transip"),
        "translated_port": alanlar.get("transport"),

        # Ag bilgileri
        "protocol": alanlar.get("proto"),
        "service": alanlar.get("service"),
        "policy_id": alanlar.get("policyid"),

        # Trafik istatistikleri
        "duration": alanlar.get("duration"),
        "sent_bytes": alanlar.get("sentbyte"),
        "received_bytes": alanlar.get("rcvdbyte"),
        "sent_packets": alanlar.get("sentpkt"),
        "received_packets": alanlar.get("rcvdpkt"),

        # Uygulama / Isletim Sistemi
        "app_category": alanlar.get("appcat"),
        "os": alanlar.get("osname"),

        # Ham log
        "raw_log": ham_metin
    }
    return normalized