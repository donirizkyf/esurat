# Panduan Kelola Akun Petugas

Dokumen ini khusus untuk super admin atau admin teknis yang mengelola akun petugas dan `super_admin` langsung dari server atau PC lokal, atau sementara melalui form web publik dengan kode registrasi internal.

## 1. Prinsip Akses

- `service_user`
  Digunakan untuk Pengguna Jasa yang mendaftar dari halaman publik.
- `monitoring`
  Digunakan untuk petugas monitoring biasa.
- `admin`
  Digunakan untuk petugas internal dengan hak lebih tinggi.
- `super_admin`
  Digunakan untuk akun utama pengelola sistem.

Petugas internal sementara bisa dibuat dari UI publik jika pemohon memiliki kode registrasi internal yang benar. Selain itu, akun juga tetap bisa dibuat lewat CLI manager.

## 2. Lokasi Database

Database aktif disimpan di file:

`C:\Users\COMPUTER\Documents\submit_document\document_submission.db`

Kalau nanti dipindah ke server lain, file ini yang perlu dibackup atau diedit.

## 3. Tool yang Dipakai

Project ini sudah punya CLI manager:

`app/manage_users.py`

Semua perintah dijalankan dari folder project:

```powershell
cd C:\Users\COMPUTER\Documents\submit_document
```

## 4. Lihat Daftar Akun

Untuk melihat semua akun:

```powershell
python -m app.manage_users list
```

Output akan menampilkan:

- `username`
- `email`
- `role`
- `status`

## 5. Membuat Akun Petugas Baru

Selain lewat CLI, akun petugas juga bisa didaftarkan dari halaman `/register` dengan memilih role `monitoring`, `admin`, atau `super_admin`, lalu memasukkan kode registrasi internal dari environment variable berikut:

- `PETUGAS_REGISTRATION_CODE` untuk `monitoring` dan `admin`
- `SUPER_ADMIN_REGISTRATION_CODE` untuk `super_admin`

Contoh membuat akun petugas monitoring:

```powershell
python -m app.manage_users create --username petugas1 --password Password123 --role monitoring --status ACTIVE
```

Contoh membuat akun admin:

```powershell
python -m app.manage_users create --username admin1 --password Password123 --role admin --status ACTIVE
```

Contoh membuat akun super admin:

```powershell
python -m app.manage_users create --username super1 --password Password123 --role super_admin --status ACTIVE
```

Kalau `--email` tidak diisi, sistem otomatis membuat email internal seperti:

`username@internal.local`

Contoh:

- `petugas1@internal.local`
- `super1@internal.local`

## 6. Mengubah Role User

Kalau ada user yang sudah ada dan ingin diubah menjadi petugas:

```powershell
python -m app.manage_users set-role --identifier user@contoh.com --role monitoring --activate
```

Atau berdasarkan username:

```powershell
python -m app.manage_users set-role --identifier petugas1 --role admin --activate
```

Catatan:

- `--identifier` bisa berupa `username` atau `email`
- `--activate` otomatis mengubah status akun menjadi `ACTIVE`

## 7. Mengubah Status Akun

Aktifkan akun:

```powershell
python -m app.manage_users set-status --identifier petugas1 --status ACTIVE
```

Ubah akun jadi pending:

```powershell
python -m app.manage_users set-status --identifier petugas1 --status PENDING
```

Status yang tersedia:

- `ACTIVE`
- `PENDING`

## 8. Login Petugas

Petugas login dari halaman:

`/login/petugas`

Petugas bisa login menggunakan:

- `username`
- atau `email`

Syarat agar berhasil login:

- role harus salah satu dari `monitoring`, `admin`, atau `super_admin`
- `account_status` harus `ACTIVE`

Setelah login:

- petugas diarahkan ke dashboard monitoring/admin
- petugas juga bisa membuka halaman `Kelola Pendaftar` untuk melihat akun `service_user`, memfilter status `PENDING`, lalu melakukan `Approve` atau `Deactivate` langsung dari web

## 9. Akun Super Admin Saat Ini

Akun yang sudah dibuat:

- `username`: `nuhrizqi`
- `email`: `nuhrizqi@internal.local`
- `role`: `super_admin`
- `status`: `ACTIVE`

Login petugas:

```text
username: nuhrizqi
password: kmzwa8awaa
```

## 10. Keamanan

Hal penting:

- Password tidak disimpan plain text di database
- Password otomatis di-hash dengan `bcrypt`
- Jangan edit kolom `password_hash` manual kecuali memang tahu format hash yang benar

Kalau ingin ganti password, cara paling aman saat ini adalah membuat ulang akun atau nanti menambahkan command `reset-password`.

## 11. Edit Langsung Database

Kalau ingin edit tabel secara manual di PC/server, bisa pakai tool seperti:

- DB Browser for SQLite
- SQLiteStudio

Tabel utama akun:

`users`

Kolom penting:

- `username`
- `email`
- `password_hash`
- `role`
- `account_status`
- `company_name`
- `business_id`
- `pic_name`

Untuk akun petugas internal, biasanya yang wajib diperhatikan hanya:

- `username`
- `email`
- `password_hash`
- `role`
- `account_status`

## 12. Rekomendasi Operasional

Untuk penggunaan harian:

- buat akun petugas lewat CLI, bukan edit raw hash manual
- gunakan `list` untuk audit cepat akun
- simpan akun internal dengan email domain internal atau `@internal.local`
- gunakan `super_admin` hanya untuk akun inti
- gunakan `monitoring` untuk petugas biasa

## 13. Cheat Sheet

Lihat semua user:

```powershell
python -m app.manage_users list
```

Buat petugas:

```powershell
python -m app.manage_users create --username petugas2 --password Password123 --role monitoring --status ACTIVE
```

Buat super admin:

```powershell
python -m app.manage_users create --username super2 --password Password123 --role super_admin --status ACTIVE
```

Naikkan role user:

```powershell
python -m app.manage_users set-role --identifier user@contoh.com --role admin --activate
```

Aktifkan akun:

```powershell
python -m app.manage_users set-status --identifier petugas2 --status ACTIVE
```
