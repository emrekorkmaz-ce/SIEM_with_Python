"""
TUM KURALLARI TEST ETME SCRIPTI

main.py'i (dinleyiciyi) AYRI bir terminalde calistirdiktan sonra,
bu scripti IKINCI bir terminalde calistir. Sirayla 6 senaryo gonderilecek,
her birinden once ne bekledigimizi ekrana basacagiz.

Test bitince alarmlar.jsonl dosyasina bak - hangi kurallarin tetiklendigini
gorebilirsin.
"""

import socket
import time

soket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
HEDEF = ("127.0.0.1", 514)


def gonder(alanlar_metni):
    """Fortinet tarzi key=value formatinda, PRI etiketiyle birlikte gonderir."""
    simdi = time.strftime("%Y-%m-%d %H:%M:%S")
    tarih, saat = simdi.split(" ")
    mesaj = f'<134>date={tarih} time={saat} devname="FW-TEST" {alanlar_metni}'
    soket.sendto(mesaj.encode(), HEDEF)


def baslik(metin):
    print("\n" + "=" * 70)
    print(metin)
    print("=" * 70)


# =========================================================
# SENARYO 0: NORMAL TRAFIK (hicbir alarm tetiklenmemeli)
# =========================================================
baslik("SENARYO 0: Normal trafik - HICBIR ALARM beklenmiyor")
for i in range(3):
    gonder('type="traffic" subtype="forward" level="notice" action=allow '
           'srcip=192.168.1.50 srcport=51234 dstip=8.8.8.8 dstport=443 '
           'proto=6 service="HTTPS" policyid=1')
    time.sleep(0.5)
print("Normal trafik gonderildi (3 istek, yavas, farkli zamanlarda).")


# =========================================================
# SENARYO 1: PORT TARAMASI (T1595)
# Beklenen: PT_PENCERE_SURESI=1sn icinde PT_ESIK=5'ten fazla FARKLI porta deny
# =========================================================
baslik("SENARYO 1: Port Taramasi (T1595) - ALARM BEKLENIYOR")
saldirgan_ip = "198.51.100.10"
hedef_ip = "10.0.0.5"
portlar = [21, 22, 23, 80, 135, 443, 445, 3389]
for port in portlar:
    gonder(f'type="traffic" subtype="forward" level="warning" action=deny '
            f'srcip={saldirgan_ip} srcport=50000 dstip={hedef_ip} dstport={port} '
            f'proto=6 service="tcp/{port}" policyid=2')
print(f"{saldirgan_ip} kaynagindan {hedef_ip} hedefine {len(portlar)} farkli porta deny gonderildi (hizli, ayni anda).")
print("Beklenti: 'Port Taramasi Supheli (MITRE T1595)' alarmi")


# =========================================================
# SENARYO 2: BRUTE FORCE (T1110)
# Beklenen: BF_PENCERE_SURESI=10sn icinde BF_ESIK=10'dan fazla AYNI ucluye deny
# =========================================================
baslik("SENARYO 2: Brute Force (T1110) - ALARM BEKLENIYOR")
saldirgan_ip = "198.51.100.20"
hedef_ip = "10.0.0.6"
hedef_port = 22   # SSH - hep AYNI port, tekrar tekrar deneniyor
for deneme in range(15):
    gonder(f'type="traffic" subtype="forward" level="warning" action=deny '
            f'srcip={saldirgan_ip} srcport=50100 dstip={hedef_ip} dstport={hedef_port} '
            f'proto=6 service="SSH" policyid=3')
print(f"{saldirgan_ip} kaynagindan {hedef_ip}:{hedef_port} hedefine 15 kez deny gonderildi (ayni port, tekrar tekrar).")
print("Beklenti: 'Brute Force Supheli (MITRE T1110)' alarmi")


# =========================================================
# SENARYO 3: DoS - TEK KAYNAK (T1498)
# Beklenen: DOS_PENCERE_SURESI=5sn icinde DOS_ESIK=200'den fazla istek (allow+deny)
# NOT: Esik gercek trafik testinden sonra 30'dan 200'e cikarildi (normal
#      DNS/uygulama trafigi 30'u rahatca asiyordu), o yuzden test yuku de artirildi.
# =========================================================
baslik("SENARYO 3: DoS Tek Kaynak (T1498) - ALARM BEKLENIYOR")
saldirgan_ip = "198.51.100.30"
hedef_ip = "10.0.0.7"
for istek in range(250):
    aksiyon = "allow" if istek % 2 == 0 else "deny"   # karisik allow/deny - action filtresi olmadigini gostermek icin
    gonder(f'type="traffic" subtype="forward" level="notice" action={aksiyon} '
            f'srcip={saldirgan_ip} srcport=50200 dstip={hedef_ip} dstport=80 '
            f'proto=6 service="HTTP" policyid=4')
print(f"{saldirgan_ip} kaynagindan {hedef_ip} hedefine 250 istek gonderildi (yari allow, yari deny, hizli).")
print("Beklenti: 'DoS Supheli - Tek Kaynak (MITRE T1498)' alarmi")


# =========================================================
# SENARYO 4: DDoS - COK KAYNAKLI (T1498)
# Beklenen: DDOS_PENCERE_SURESI=5sn icinde DDOS_ESIK=20'den fazla FARKLI kaynak
# =========================================================
baslik("SENARYO 4: DDoS Cok Kaynakli (T1498) - ALARM BEKLENIYOR")
hedef_ip = "10.0.0.8"   # botnet hedefi - tek bir sunucu
for i in range(25):
    # her seferinde FARKLI bir kaynak IP simule ediyoruz (botnet gibi)
    sahte_kaynak = f"203.0.113.{i}"
    gonder(f'type="traffic" subtype="forward" level="warning" action=deny '
            f'srcip={sahte_kaynak} srcport=51000 dstip={hedef_ip} dstport=443 '
            f'proto=6 service="HTTPS" policyid=5')
print(f"{hedef_ip} hedefine 25 FARKLI kaynak IP'den istek gonderildi (botnet simulasyonu).")
print("Beklenti: 'DDoS Supheli - Cok Kaynakli (MITRE T1498)' alarmi")


# =========================================================
# SENARYO 5: GURULTU FILTRESI TESTI (broadcast/multicast)
# Beklenen: HICBIR ALARM - bu trafik yoksayilmali
# =========================================================
baslik("SENARYO 5: Broadcast/Multicast gurultusu - HICBIR ALARM beklenmiyor")
kaynak_ip = "192.168.1.28"
# IPv4 broadcast hedefi - port taramasi/brute force/dos kurallarini tetikleyebilecek kadar tekrar
for port in range(20):
    gonder(f'type="traffic" subtype="forward" level="notice" action=deny '
            f'srcip={kaynak_ip} srcport=50300 dstip=192.168.1.255 dstport={54900+port} '
            f'proto=17 service="udp" policyid=6')
print(f"{kaynak_ip} kaynagindan broadcast adresine (192.168.1.255) 20 farkli porta istek gonderildi.")
print("Beklenti: HICBIR alarm (broadcast filtrelenmis olmali)")


print("\n" + "=" * 70)
print("TUM SENARYOLAR GONDERILDI.")
print("Simdi 'alarmlar.jsonl' dosyasini ac ve hangi kurallarin tetiklendigini kontrol et.")
print("Beklenen: Senaryo 1,2,3,4 icin birer alarm; Senaryo 0 ve 5 icin HICBIR alarm.")
print("=" * 70)