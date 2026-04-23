# Sistem Pengajuan Dokumen

Aplikasi web berbasis FastAPI untuk pengajuan dokumen oleh `service_user` dan pengelolaan dokumen oleh petugas internal dengan role `monitoring`, `admin`, dan `super_admin`.

## Fitur Inti

- Registrasi dan login Pengguna Jasa
- Login Petugas internal
- Dashboard pengguna untuk upload dan pantau dokumen
- Dashboard admin/monitoring untuk verifikasi dokumen
- Upload file hasil dokumen oleh petugas
- Pembuatan tanda terima PDF otomatis dengan signature token dari server
- Audit log aktivitas utama

## Perbedaan Role Internal

- `monitoring`
  Bertugas meninjau antrean dokumen dan melakukan screening awal. Role ini bisa melihat dashboard internal, membuka detail dokumen, dan menolak dokumen dengan catatan, tetapi tidak bisa menyetujui dokumen, menandai proses, mengunggah hasil akhir, atau membuka halaman kelola pendaftar.
- `admin`
  Bertugas menjalankan operasi layanan. Role ini bisa melakukan seluruh tugas `monitoring`, menyetujui dokumen, menandai dokumen sedang diproses, mengunggah hasil akhir, dan mengaktifkan akun `service_user` dari halaman `Kelola Pendaftar`.
- `super_admin`
  Bertugas mengendalikan akun dan hak akses. Role ini memiliki seluruh hak `admin`, serta dapat menonaktifkan akun `service_user`. Role ini disiapkan sebagai level tertinggi untuk pengelolaan sistem dan akun internal.

## Teknologi

- FastAPI
- SQLAlchemy
- Jinja2
- SQLite
- ReportLab
- Session-based authentication

## Menjalankan Proyek

1. Install dependency:

```powershell
pip install -r requirements.txt
```

2. Jalankan server:

```powershell
python -m uvicorn app.main:app --reload --port 8010
```

3. Buka aplikasi:

`http://127.0.0.1:8010`

Project ini otomatis membaca file `.env` di root folder saat aplikasi atau CLI dijalankan secara lokal.

## Konfigurasi Opsional

Variabel environment yang didukung:

- `DATABASE_PATH`
- `SESSION_SECRET_KEY`
- `SESSION_HTTPS_ONLY`
- `PETUGAS_REGISTRATION_CODE`
- `SUPER_ADMIN_REGISTRATION_CODE`
- `RECEIPT_SIGNATURE_SECRET`

## Aktivasi Akun

- akun `service_user` hasil registrasi web selalu dibuat dengan status `PENDING`
- akun `service_user` harus diaktifkan dulu oleh petugas dari halaman `Kelola Pendaftar`
- akun petugas hasil registrasi web menjadi `ACTIVE` jika kode registrasi internal valid

## Deploy ke Railway

Project ini sudah menyertakan `Procfile` dan `railway.json` agar Railway bisa langsung menjalankan FastAPI dengan `uvicorn`.

Environment variable yang disarankan di Railway:

- `SESSION_SECRET_KEY`
- `SESSION_HTTPS_ONLY=true`
- `PETUGAS_REGISTRATION_CODE`
- `SUPER_ADMIN_REGISTRATION_CODE`
- `RECEIPT_SIGNATURE_SECRET`

## Kelola Akun Petugas

Contoh perintah untuk membuat akun petugas:

```powershell
python -m app.manage_users create --username petugas1 --password Password123 --role monitoring --status ACTIVE
```

Lihat panduan lengkap di [README_KELOLA_AKUN_PETUGAS.md](README_KELOLA_AKUN_PETUGAS.md) dan alur demo di [MANUAL_DEMO.md](MANUAL_DEMO.md).
