# Manual Demo Sistem Pengajuan Dokumen

## 1. Tujuan

Dokumen ini dipakai untuk mendemokan aplikasi yang sudah berjalan dengan backend FastAPI, database SQLite, autentikasi berbasis session, upload PDF, dashboard pengguna, dan dashboard monitoring.

Manual ini cocok dipakai untuk:

- presentasi internal
- demo ke stakeholder
- uji alur fitur utama
- panduan operator saat menyiapkan demo

## 2. Ringkasan Peran Pengguna

Sistem saat ini memiliki 2 kelompok besar pengguna:

### Pengguna Jasa

- bisa daftar dari halaman publik
- login dari halaman `Login Pengguna Jasa`
- setelah login masuk ke dashboard pengajuan
- bisa upload dokumen PDF
- bisa lihat status dokumen
- bisa download tanda terima
- bisa download file hasil jika dokumen sudah selesai

### Petugas Internal

Terdiri dari:

- `monitoring`
- `admin`
- `super_admin`

Petugas internal:

- sementara bisa didaftarkan dari form web publik dengan memilih role petugas dan memasukkan kode registrasi internal
- akunnya dibuat langsung di database atau lewat CLI manager
- login dari halaman `Login Petugas`
- setelah login masuk ke dashboard monitoring/admin

## 3. Fitur yang Bisa Didemo

Fitur aplikasi yang saat ini benar-benar tersedia:

1. Halaman awal dengan 3 pilihan akses.
2. Registrasi Pengguna Jasa.
3. Registrasi akun petugas via web dengan kode internal.
4. Login Pengguna Jasa.
5. Login Petugas.
6. Dashboard Pengguna Jasa.
7. Upload dokumen PDF.
8. Penyimpanan metadata dokumen ke database.
9. Pembuatan tanda terima PDF otomatis.
10. Detail dokumen pengguna.
11. Dashboard monitoring/admin.
12. Filter status dokumen.
13. Approve, reject, dan mark as processed.
14. Upload file hasil oleh admin.
15. Download file hasil oleh pengguna.
16. Audit log aktivitas utama.
17. Monitoring pendaftar baru dan verifikasi akun dari dashboard petugas.

## 4. Persiapan Sebelum Demo

1. Masuk ke folder project:

```powershell
cd C:\Users\COMPUTER\Documents\submit_document
```

2. Jalankan server:

```powershell
python -m uvicorn app.main:app --reload --port 8010
```

3. Buka browser:

`http://127.0.0.1:8010`

4. Pastikan akun petugas sudah ada.

Contoh akun yang sudah dibuat:

- `username`: `nuhrizqi`
- `role`: `super_admin`

5. Siapkan minimal 1 file PDF kecil untuk demo upload.

## 5. Data Demo yang Disarankan

### Akun Pengguna Jasa

Kalau ingin demo pendaftaran:

- nama perusahaan: `PT Demo Nusantara`
- email: `demo@perusahaan.com`
- nomor izin/NIB/NPWP: `1234567890`
- PIC: `Andi Pratama`
- password: `Password123`

### Akun Petugas

Contoh akun petugas yang aktif:

- username: `nuhrizqi`
- password: `kmzwa8awaa`

## 6. Skenario Demo Utama

### A. Pembukaan

Narasi:

"Ini adalah sistem pengajuan dokumen berbasis web yang memisahkan akses antara Pengguna Jasa dan Petugas Monitoring. Pengguna Jasa dapat mendaftar dan mengajukan dokumen, sedangkan petugas memverifikasi dan menyelesaikan proses dokumen dari dashboard internal."

Yang dicek:

- halaman awal tampil normal
- ada 3 pilihan akses
- tampilan responsif dan sidebar konsisten

### B. Demo Halaman Awal

Tunjukkan 3 opsi:

1. `Daftar Pengguna Jasa`
2. `Login Pengguna Jasa`
3. `Login Petugas`

Narasi:

"Pemisahan ini dibuat supaya akun publik dan akun internal tidak tercampur. Petugas internal tidak dibuat lewat form daftar umum."
"Pemisahan akses tetap ada di halaman login, tetapi sementara pendaftaran perusahaan dan petugas dapat dilakukan dari satu form web dengan kontrol role dan kode registrasi internal."

### C. Demo Registrasi Pengguna Jasa

Langkah:

1. Klik `Daftar Pengguna Jasa`.
2. Isi data perusahaan.
3. Submit form.

Yang dicek:

- field perusahaan muncul lengkap
- validasi form berjalan
- sistem menampilkan pesan sukses
- akun bisa menjadi `PENDING` atau `ACTIVE` tergantung konfigurasi

Narasi:

"Pengguna Jasa mengisi data perusahaan, PIC, dan kredensial login dari halaman publik."

### D. Demo Login Pengguna Jasa

Langkah:

1. Buka `Login Pengguna Jasa`.
2. Login memakai email dan password.
3. Pastikan diarahkan ke dashboard pengguna.

Yang dicek:

- login hanya menerima akun role `service_user`
- akun yang belum aktif ditolak
- redirect ke dashboard pengguna berjalan

### E. Demo Dashboard Pengguna Jasa

Langkah:

1. Tunjukkan dashboard pengguna.
2. Jelaskan bahwa ini adalah area pemantauan dokumen milik perusahaan yang sedang login.
3. Tunjukkan daftar dokumen yang pernah diajukan.

Yang dicek:

- tabel dokumen hanya menampilkan dokumen milik user yang login
- badge status tampil konsisten
- tombol detail dokumen tersedia

### F. Demo Upload Dokumen

Langkah:

1. Kembali ke halaman pengajuan dokumen.
2. Isi:
   - perihal
   - tanggal
   - deskripsi
   - file PDF
3. Klik `Ajukan Dokumen`.

Yang dicek:

- hanya PDF yang diterima
- ukuran file maksimal 5 MB
- dokumen tersimpan ke folder `uploads`
- metadata tersimpan ke database
- status awal menjadi `DIAJUKAN`
- document ID dibuat otomatis
- receipt PDF dibuat otomatis

Narasi:

"Saat dokumen diajukan, sistem langsung menyimpan file, metadata, audit log, dan membuat tanda terima PDF."

### G. Demo Detail Dokumen Pengguna

Langkah:

1. Buka detail salah satu dokumen.
2. Tunjukkan:
   - document ID
   - status
   - file asli
   - receipt
   - hasil akhir jika tersedia

Yang dicek:

- tombol `Download Receipt` muncul
- tombol `Download Result` hanya muncul jika file hasil sudah ada
- admin notes tampil jika dokumen pernah ditolak

### H. Demo Login Petugas

Langkah:

1. Logout dari akun pengguna.
2. Buka `Login Petugas`.
3. Login memakai akun petugas internal.

Yang dicek:

- hanya role `monitoring`, `admin`, atau `super_admin` yang bisa masuk
- redirect ke dashboard monitoring/admin berjalan

Narasi:

"Akun petugas dikelola langsung dari database atau CLI manager, bukan dari halaman publik."

### I. Demo Dashboard Monitoring/Admin

Langkah:

1. Tunjukkan dashboard monitoring.
2. Tunjukkan tabel semua dokumen.
3. Coba filter berdasarkan status.

Yang dicek:

- seluruh dokumen terlihat oleh petugas
- filter status bekerja
- tombol detail dokumen admin tersedia

### J. Demo Aksi Petugas

Langkah:

1. Buka detail dokumen dari sisi admin.
2. Lakukan salah satu aksi:
   - `Approve`
   - `Mark as Processed`
   - `Reject` dengan catatan

Yang dicek:

- status dokumen berubah
- reject menyimpan catatan admin
- audit log bertambah

Narasi:

"Petugas dapat memverifikasi, memproses, atau menolak dokumen dengan catatan yang akan terlihat di sisi pengguna."

### K. Demo Upload Hasil Dokumen

Langkah:

1. Dari detail admin, upload file hasil PDF.
2. Simpan hasil.

Yang dicek:

- file PDF hasil masuk ke folder `outputs`
- relasi file hasil ke dokumen tersimpan
- status berubah menjadi `SELESAI`

### L. Demo Download Hasil oleh Pengguna

Langkah:

1. Login lagi sebagai Pengguna Jasa.
2. Buka detail dokumen yang sudah selesai.
3. Klik `Download Result`.

Yang dicek:

- file hasil bisa diunduh
- receipt juga tetap tersedia

## 7. Checklist Verifikasi

Gunakan checklist ini sebelum demo:

- server FastAPI berjalan
- halaman awal tampil normal
- registrasi Pengguna Jasa bekerja
- login Pengguna Jasa bekerja
- login Petugas bekerja
- upload PDF berhasil
- receipt PDF dibuat
- dashboard pengguna menampilkan data yang benar
- dashboard monitoring menampilkan semua data
- filter status admin bekerja
- approve / reject / process berjalan
- upload hasil admin berjalan
- pengguna bisa download file hasil

## 8. Bukti File dan Data

Lokasi file penting:

- upload dokumen: `uploads`
- output hasil: `outputs`
- database: `document_submission.db`

Tabel penting di database:

- `users`
- `document_submissions`
- `audit_logs`

## 9. Audit Log yang Bisa Ditunjukkan

Sistem saat ini mencatat aktivitas:

- `login`
- `upload`
- `verify`
- `download`

Narasi:

"Setiap aktivitas penting dicatat di audit log, termasuk siapa yang login, siapa yang upload dokumen, siapa yang memverifikasi, dan siapa yang mengunduh file."

## 10. Batasan Saat Ini

Beberapa hal yang masih bisa dikembangkan:

- belum ada UI khusus manajemen user oleh super admin
- belum ada reset password dari dashboard
- belum ada halaman audit log di frontend
- belum ada migrasi database formal seperti Alembic

Namun untuk demo aplikasi inti, alur utama sudah berjalan end-to-end.

## 11. Penutup Demo

Contoh penutup:

"Sistem ini sudah mendukung alur nyata dari pendaftaran Pengguna Jasa, pengajuan dokumen, monitoring internal, verifikasi petugas, sampai upload hasil akhir dan download oleh pengguna. Tahap berikutnya bisa difokuskan ke manajemen user internal, penguatan keamanan, dan deployment ke server produksi."
