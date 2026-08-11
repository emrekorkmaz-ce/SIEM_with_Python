"""
Ana dosya - socket'i acar, kuyrugu yonetir, thread'leri baslatir.
Butun mantik (normalizasyon, kurallar) baska dosyalardan import edilir,
burada sadece "orkestra sefligi" yapilir.
"""

import socket
import threading
import queue
import time

import ayarlar
from normalizasyon import normalize_et
from io_yardimci import jsonl_yaz, alarm_kontrol_ve_yaz
from kural_port_tarama import port_taramasi_kontrol_et
from kural_bruteforce import bruteforce_kontrol_et
from kural_dos import dos_kontrol_et
from kural_ddos import ddos_kontrol_et


benim_soketim = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
benim_soketim.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, ayarlar.SOCKET_BUFFER_BOYUTU)
benim_soketim.bind((ayarlar.DINLEME_IP, ayarlar.DINLEME_PORT))

log_kuyrugu = queue.Queue(maxsize=ayarlar.KUYRUK_MAX_BOYUT)

# --- TUM AKTIF KURALLAR BURADA LISTELENIR ---
# Yeni bir kural eklemek istediginde: ilgili dosyada fonksiyonu yaz,
# yukarida import et, sonra bu listeye ekle. isleyici_thread icinde
# baska HICBIR SEY degistirmen gerekmez.
AKTIF_KURALLAR = [
    port_taramasi_kontrol_et,
    bruteforce_kontrol_et,
    dos_kontrol_et,
    ddos_kontrol_et,
]


def dinleyici_thread():
    """SADECE veriyi kapip kuyruga atar. Baska HICBIR is yapmaz."""
    while True:
        veri, kimden_geldi = benim_soketim.recvfrom(65535)
        try:
            log_kuyrugu.put_nowait((veri, kimden_geldi, time.time()))
        except queue.Full:
            print("UYARI: Kuyruk dolu, bir kayit atlandi!")


def isleyici_thread():
    """Kuyruktan alir, normalize eder, dosyaya yazar, kurallari calistirir."""

    with open(ayarlar.LOG_DOSYASI, "a", encoding="utf-8") as dosya, \
         open(ayarlar.ALARM_DOSYASI, "a", encoding="utf-8") as alarm_dosyasi:

        while True:
            veri, kimden_geldi, zaman = log_kuyrugu.get()

            normalized = normalize_et(veri, kimden_geldi, zaman)
            jsonl_yaz(normalized, dosya)

            # Tum aktif kurallari sirayla calistir - her biri icin
            # tek satir yeterli, dosya yazma/json/print detaylarini
            # elle tekrar tekrar yazmiyoruz
            for kural_fonksiyonu in AKTIF_KURALLAR:
                alarm_kontrol_ve_yaz(kural_fonksiyonu, normalized, alarm_dosyasi)

            log_kuyrugu.task_done()


if __name__ == "__main__":
    threading.Thread(target=dinleyici_thread, daemon=True).start()
    threading.Thread(target=isleyici_thread, daemon=True).start()

    print("Dinlemeye basladim (modul mod)... Ctrl+C ile durdur.")

    while True:
        time.sleep(1)