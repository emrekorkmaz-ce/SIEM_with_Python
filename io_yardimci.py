"""
Dosyaya JSON satiri yazma islemini tek bir yerde topluyoruz.

Neden gerekli: main.py'da her kural icin ayni 4 satirlik kalibi
(json.dumps + print + write + flush) elle tekrar tekrar yazmak,
kopyala-yapistir hatalarina acik kapi birakiyordu (nitekim bir kez
yanlis degiskeni yazma hatasi yasadik). Bu fonksiyon o riski ortadan
kaldirir: parametreleri veriyoruz, geri kalanini o hallediyor.
"""

import json


def jsonl_yaz(veri, dosya, ekran_onegi=None):
    """
    Bir dictionary'yi JSON satirina cevirip hem dosyaya yazar hem
    (istenirse) ekrana basar.

    veri:          yazilacak dictionary (orn. normalized log ya da alarm detayi)
    dosya:         acik bir dosya handle'i (with open(...) as dosya bloğundan gelen)
    ekran_onegi:   None ise sadece JSON'u ekrana basar (normal log satirlari icin).
                   Bir metin verilirse (orn. "!!! ALARM !!!") o onekle basar.
    """
    satir = json.dumps(veri, ensure_ascii=False)

    if ekran_onegi:
        print(ekran_onegi, satir)
    else:
        print(satir)

    dosya.write(satir + "\n")
    dosya.flush()


def alarm_kontrol_ve_yaz(kontrol_fonksiyonu, normalized, alarm_dosyasi):
    """
    Bir kural fonksiyonunu (orn. port_taramasi_kontrol_et) calistirir,
    alarm varsa otomatik olarak dosyaya yazar ve ekrana basar.

    Bu sayede main.py'daki her kural cagrisi TEK SATIRA iner, ve
    'yanlis degiskeni yazma' turu hatalar yapisal olarak imkansiz hale gelir
    - cunku hangi degiskenin yazilacagini biz elle sec mek zorunda degiliz,
    fonksiyonun kendisi hallediyor.
    """
    alarm_var_mi, alarm_detay = kontrol_fonksiyonu(normalized)
    if alarm_var_mi:
        jsonl_yaz(alarm_detay, alarm_dosyasi, ekran_onegi="!!! ALARM !!!")
    return alarm_var_mi