import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import socket
import os
import threading
from datetime import datetime
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, WhoisLookupError
from concurrent.futures import ThreadPoolExecutor

# İşlemi yapan ana fonksiyon
def get_ip_info(ip):
    # Varsayılan veriler
    data = {
        "IP": ip, 
        "Country": "Unknown", # Yeni Kolon
        "Owner": "Unknown", 
        "ASN": "Unknown", 
        "Reverse_DNS": "Unknown"
    }
    
    # 1. Reverse DNS Sorgusu (Zaman alabilir, o yüzden try-except önemli)
    try:
        # Timeout ekledik ki yanıt vermeyen IP programı kitlemesin
        socket.setdefaulttimeout(2) 
        hostname, _, _ = socket.gethostbyaddr(ip)
        data["Reverse_DNS"] = hostname
    except (socket.herror, socket.timeout, Exception):
        data["Reverse_DNS"] = "No Reverse DNS"
    
    # 2. Whois / RDAP Sorgusu
    try:
        obj = IPWhois(ip)
        # timeout parametresi kütüphane versiyonuna göre değişebilir ama genel hız için RDAP kullanıyoruz
        results = obj.lookup_rdap(retry_count=1, depth=1)
        
        data["Owner"] = results.get('network', {}).get('name')
        data["ASN"] = results.get('asn_description')
        data["Country"] = results.get('asn_country_code') # Ülke Kodu (TR, US, DE vs.)
        
    except (IPDefinedError, WhoisLookupError, Exception):
        data["Owner"] = "Error/Private IP"
        
    return data

def start_processing():
    file_path = filedialog.askopenfilename(title="IP listesi seç", filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return
    
    # Butonu pasif yapalım ki üst üste basılmasın
    btn.config(state="disabled", text="İşleniyor... Lütfen Bekleyin")
    link_label.config(text="Tarama başladı, IP sayısına göre biraz sürebilir...")
    
    # Arayüz donmasın diye işlemi arka planda (Thread) başlatıyoruz
    threading.Thread(target=run_bulk_scan, args=(file_path,), daemon=True).start()

def run_bulk_scan(file_path):
    try:
        # Dosya okuma
        with open(file_path, 'r') as f:
            ip_list = [line.strip() for line in f if line.strip()]

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(os.path.dirname(file_path), f"sonuclar_{timestamp}.csv")
        
        results_data = []

        # --- PARALEL İŞLEM KISMI (HIZLANDIRICI) ---
        # max_workers=50: Aynı anda 50 IP'yi sorgular. Bilgisayarın CPU gücüne göre artırılıp azaltılabilir.
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Tüm IP'leri executor'a gönderiyoruz, sonuçları topluyoruz
            results_data = list(executor.map(get_ip_info, ip_list))

        # Sonuçları Yazma
        with open(output_file, 'w', newline='', encoding='utf-8') as f_out:
            fieldnames = ["IP", "Country", "Owner", "ASN", "Reverse_DNS"]
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results_data)

        # İşlem bitince arayüzü güncelle
        def finish_ui():
            btn.config(state="normal", text="TXT Dosyası Seç ve Çalıştır")
            link_label.config(text=f"Bitti! Dosya: {output_file}")
            link_label.bind("<Button-1>", lambda e: os.startfile(output_file))
            messagebox.showinfo("Başarılı", f"İşlem tamamlandı.\n{len(ip_list)} IP tarandı.")

        root.after(0, finish_ui)

    except Exception as e:
        root.after(0, lambda: messagebox.showerror("Hata", str(e)))
        root.after(0, lambda: btn.config(state="normal", text="TXT Dosyası Seç ve Çalıştır"))

# Tkinter Arayüzü
root = tk.Tk()
root.title("IP Whois Pro (Hızlı & Lokasyonlu)")
root.geometry("400x200")

label_info = tk.Label(root, text="Listeyi seçin, e; zamanli IP taramasi yapilacaktir.", pady=10)
label_info.pack()

btn = tk.Button(root, text="TXT Dosyası Seç ve Çalıştır", command=start_processing, bg="#dddddd", height=2)
btn.pack(padx=20, pady=10, fill="x")

link_label = tk.Label(root, text="", fg="blue", cursor="hand2", wraplength=380)
link_label.pack(padx=20, pady=10)

root.mainloop()