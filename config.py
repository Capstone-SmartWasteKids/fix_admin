import os
from datetime import timedelta

class Config:
    SECRET_KEY = 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0' 

    # Konfigurasi Database MySQL
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'       
    MYSQL_PASSWORD = ''       
    MYSQL_DB = 'smartwaste_db'
    
    # Gunakan DictCursor agar mudah memanggil data dengan nama kolom
    MYSQL_CURSORCLASS = 'DictCursor'

    # --- KONFIGURASI SESI / TOKEN ---
    # 1. Menentukan masa aktif token (Misal: 1 Hari)
    # Jika browser ditutup, user tetap bisa masuk otomatis selama belum lewat 1 hari.
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)

    # 2. Sliding Expiration (PENTING UNTUK REQUEST ANDA)
    # Jika True: Setiap kali admin klik/refresh halaman, timer kadaluarsa di-reset ulang.
    # Timer hanya berjalan murni ketika admin 'idle' atau menutup web.
    SESSION_REFRESH_EACH_REQUEST = True