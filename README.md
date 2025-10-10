# SQL Sword — SQL Injection Automation


**SQL Sword** adalah tool GUI/CLI sederhana untuk *SQL injection automation* (inspirasi: **sqlmap**).

---

# Fitur utama

* UI berbasis `tkinter` / `ttkbootstrap` (GUI ringan)
* Scanner *union-based* SQLi (struktur project untuk dikembangkan)
* Database Explorer
* Mudah diperluas (modular): tambahkan payload, modul teknik, logging

---

---

# Persyaratan

Gunakan Python 3.8+. Dependensi minimal disimpan di `requirements.txt`:

```
requests>=2.28.0
ttkbootstrap>=1.6.0
# Optional: Pillow untuk manipulasi gambar
# Pillow>=9.0.0
```

**Catatan platform**

* Linux (Debian/Ubuntu): jika `tkinter` belum tersedia, install `python3-tk`.
* Windows/macOS: biasanya sudah terpasang bersama Python installer resmi.

---

# Instalasi cepat

```bash
# (opsional) buat virtual environment
python -m venv .venv
# activate (.venv\Scripts\activate untuk Windows)
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

---

# Kontribusi

1. Fork repo
2. Buat branch fitur: `feature/namafitur`
3. Commit dan push, lalu ajukan PR
4. Sertakan test bila perlu

Silakan tambahkan module scanning (payloads, taming false positives), fitur proxy, dan reporting.

---

# Lisensi

Direkomendasikan: **MIT License**. Contoh header singkat yang bisa kamu masukkan di `LICENSE`:

```
MIT License

Copyright (c) 2025 Peluru Kertas

Permission is hereby granted, free of charge, to any person obtaining a copy...
```

*(lengkapi file LICENSE dengan text MIT standar).*

---

# Disclaimer & Etika

Tool ini ditujukan untuk tujuan penelitian keamanan **dengan izin**. Jangan gunakan untuk aktivitas ilegal atau tanpa izin eksplisit dari pemilik sistem. Penulis tidak bertanggung jawab atas penyalahgunaan.

---

# Kontak

* Author: Peluru Kertas
* Project: SQL Sword — SQL Injection Automation




