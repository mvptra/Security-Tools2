# USB Alarm

Skrip Python untuk Windows yang memantau drive baru. Saat perlindungan aktif,
penyimpanan USB dibuat **hanya-baca** (data tidak bisa disalin ke flashdisk),
dan jika ada drive baru yang tidak ada di whitelist, skrip membunyikan alarm
dengan **petunjuk suara**, **mengunci Windows**, lalu menampilkan layar merah
yang baru hilang setelah sandi kedua benar.

Dibuat sebagai proyek belajar: registry Windows, Task Scheduler, Tkinter,
threading, penyimpanan sandi sebagai hash, dan pembatasan percobaan sandi.

> ⚠️ **Disclaimer:** Ini tool pembelajaran dan **bukan** pengganti keamanan
> sistem. Gunakan hanya di komputer milik sendiri. Baca bagian
> [Batasan](#batasan) sebelum mengandalkannya.

## Screenshot

![Layar alarm](screenshot.png)

## Perintah

Pemakaian: `python usb_lockdown.py <perintah>`

| Perintah | Fungsi | Sandi diminta? |
|---|---|---|
| `help` | Menampilkan daftar perintah | Tidak |
| `manual` | Menyalakan perlindungan di CMD ini, aktif selama jendelanya terbuka | Tidak (sandi dibuat saat pertama kali) |
| `auto-on` | Mendaftarkan skrip agar menyala sendiri setiap Windows login | Tidak (sandi dibuat saat pertama kali) |
| `auto-off` | Membatalkan penyalaan otomatis. File skrip tidak dihapus | **Ya** |
| `status` | Melihat sandi, pemblokiran USB, mode otomatis, dan apakah pemantauan berjalan | Tidak |
| `test-sound` | Memutar sirene dan semua ucapan untuk menguji, tanpa mengunci apa pun | Tidak |
| `unblock` | Membatalkan pemblokiran USB hanya-baca | **Ya** |
| `set-password` | Membuat atau mengganti sandi | **Ya** (jika sandi sudah ada) |

Semua perintah selain `help`, `status`, dan `test-sound` butuh **CMD sebagai Administrator**
(karena mengubah registry atau Task Scheduler).

Menyalakan perlindungan tidak butuh sandi, karena itu tidak merugikan pemilik.
Yang butuh sandi adalah perintah yang **mematikan** perlindungan.

## Dua sandi

| | Sandi utama | Sandi kedua |
|---|---|---|
| Isinya | Sandi Windows akunmu | Sandi buatan di skrip ini |
| Dipakai untuk | Mematikan perlindungan lewat CMD (bersama sandi kedua) | Mematikan alarm di layar merah, dan mematikan perlindungan lewat CMD (bersama sandi utama) |

- Untuk `auto-off`, `unblock`, `set-password`, dan menghentikan mode `manual`
  (Ctrl+C), skrip meminta **sandi utama lalu sandi kedua**. Keduanya harus benar.
- Di layar merah hanya sandi kedua yang diminta, karena sandi Windows sudah
  dimasukkan di layar kunci.
- Sandi kedua disimpan sebagai **hash PBKDF2-SHA256 dengan salt acak**, bukan
  teks biasa, di `C:\ProgramData\USBAlarm\config.json`. Sandi Windows tidak
  pernah disimpan.
- Sandi minimal 8 karakter. Saat diketik, tiap karakter tampil sebagai `*`
  (Backspace untuk menghapus), dan dua kali salah-ketik tidak dihukum. Mulai **kesalahan ke-3** ada jeda 30 detik, lalu 60, 120, dan
  seterusnya sampai maksimal 15 menit. Jeda tersimpan di file konfigurasi,
  jadi tidak hilang kalau skrip dijalankan ulang.
- Kalau kamu masuk Windows memakai **PIN atau sidik jari**, PIN tidak bisa
  diverifikasi sebagai sandi utama. Saat pengaturan sandi, pilih opsi
  **"Buat sandi utama terpisah di skrip"**.
- Sandi Windows yang salah dihitung Windows sebagai percobaan login gagal.
  Pada pengaturan tertentu, terlalu banyak yang salah bisa mengunci akunmu.

Jangan memakai sandi yang sama untuk sandi kedua dan sandi Windows. Skrip tidak
bisa memeriksanya.

## Alur saat flashdisk dicolok

| Tahap | Yang terjadi | Suara |
|---|---|---|
| 1. Drive baru terdeteksi | Windows langsung dikunci | "Peringatan. Aktivitas mencurigakan terdeteksi." |
| 2. Layar kunci Windows | Menunggu kamu mengetik sandi Windows (sandi utama) | Sirene, lalu "Silakan masukkan kata sandi utama." Bergantian berulang |
| 3. Setelah login | Layar merah muncul dan meminta sandi kedua | Sirene, lalu "Silakan masukkan kata sandi kedua." Bergantian berulang |
| 4. Sandi kedua benar | Alarm berhenti, layar merah hilang | "Silakan melanjutkan aktivitas, Tuan." |

Setiap kejadian dicatat di `C:\ProgramData\USBAlarm\events.log`.

## Instalasi

Butuh Python 3 di Windows. Tidak ada library tambahan, karena `tkinter`,
`winreg`, dan `winsound` sudah bawaan Python di Windows.

Taruh skrip di **folder tetap di laptop**, misalnya `C:\usb-alarm\`, bukan di
flashdisk. Mode otomatis menyimpan lokasi file ini, jadi jika folder dipindah
atau dihapus, penyalaan otomatisnya gagal.

```bat
git clone https://github.com/mvptra/usb-alarm.git C:\usb-alarm
cd C:\usb-alarm
```

## Cara pakai

Buka CMD dengan **Run as administrator**, lalu masuk ke folder skrip.

**Mode manual** (perlindungan hanya aktif saat kamu menjalankannya):

```bat
python usb_lockdown.py manual
```

Saat pertama kali, skrip meminta kamu membuat sandi. Untuk berhenti, tekan
Ctrl+C lalu masukkan sandi utama dan sandi kedua. Menutup jendela CMD dengan
tombol X juga menghentikan pemantauan, tetapi pemblokiran USB tetap menyala
(lihat [Batasan](#batasan)).

**Mode otomatis** (menyala sendiri setiap login):

```bat
python usb_lockdown.py auto-on
python usb_lockdown.py status
```

Setelah `auto-on`, login ulang atau restart, lalu cek dengan `status` bahwa
"Pemantauan berjalan: ya". Untuk membatalkan: `python usb_lockdown.py auto-off`.

Drive internal selain `C:` yang ingin diabaikan ditambahkan ke
`WHITELIST_DRIVES` di bagian konfigurasi skrip, misalnya `{"C:", "D:"}`.

## Suara dan ucapan

Ada dua jenis suara: **sirene** dan **ucapan**.

**Sirene.** Skrip memutar `alarm.wav` yang ada di folder yang sama dengan
`usb_lockdown.py`. Repo ini menyertakan sirene yang dibuat sendiri lewat skrip
Python, jadi bebas dipakai. Jika file tidak ada atau gagal diputar, alarm
memakai beep. Hanya format `.wav` yang didukung.

**Ucapan.** Secara bawaan kalimatnya diucapkan oleh suara komputer Windows
(`System.Speech`, dipanggil lewat PowerShell). Skrip memilih suara berbahasa
Indonesia jika terpasang. **Jika tidak ada, kalimat Indonesia akan dibaca
dengan suara bahasa lain dan bisa terdengar aneh.** Nama suara yang dipakai
ditampilkan oleh `test-sound`. Untuk menambah suara Indonesia, cek
Settings > Time & language > Speech (ketersediaan tergantung versi Windows).

**Suara sendiri.** Kalau suara komputer tidak enak didengar, rekam suaramu atau
buat dengan layanan lain, simpan sebagai `.wav`, lalu taruh di folder skrip
dengan nama berikut. File ini menggantikan suara komputer untuk tahap itu:

| Nama file | Kalimat |
|---|---|
| `suara_peringatan.wav` | Aktivitas mencurigakan terdeteksi |
| `suara_sandi_utama.wav` | Silakan masukkan kata sandi utama |
| `suara_sandi_kedua.wav` | Silakan masukkan kata sandi kedua |
| `suara_selesai.wav` | Silakan melanjutkan aktivitas, Tuan |

Kalimatnya bisa diubah di `VOICE_PHRASES` pada bagian konfigurasi skrip.
Ucapan dimatikan dengan `VOICE_ENABLED = False`.

Uji semuanya tanpa memicu alarm sungguhan:

```bat
python usb_lockdown.py test-sound
```

Perintah itu memutar sirene lalu keempat kalimat, dan menampilkan sumber suara
tiap kalimat (file sendiri atau suara komputer). Jika ada yang gagal, tertulis
GAGAL dan penyebabnya dicatat di `events.log`.

## Pemblokiran USB (hanya-baca)

Skrip mengatur nilai registry `WriteProtect` di
`HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`. Dengan nilai 1,
Windows menolak penulisan ke penyimpanan USB, tetapi isinya masih bisa dibaca.

- Pemblokiran aktif **selama perlindungan menyala**, jadi **flashdisk milikmu
  sendiri juga hanya-baca**. Gunakan `unblock` (atau `auto-off` lalu `unblock`)
  jika perlu menulis ke flashdisk sendiri.
- Pemblokiran **tetap menyala** walaupun skrip berhenti mendadak. Untuk
  membatalkannya, gunakan `unblock`.
- Setelah `unblock`, pemblokiran baru aktif lagi saat perlindungan dinyalakan
  kembali (menjalankan `manual`, atau login ulang pada mode otomatis).

## Batasan

Skrip ini **tidak** menjamin data aman. Hal yang perlu diketahui:

- **Hanya menutup satu jalur:** menyalin data ke flashdisk. Data masih bisa
  keluar lewat internet, email, cloud, HP via MTP, atau foto layar.
- **Tidak melindungi dari virus di flashdisk.** Flashdisk masih bisa dibaca,
  jadi file berbahaya di dalamnya tetap berbahaya jika dibuka.
- **Tidak menghentikan keyboard atau mouse USB palsu.** Perangkat jenis itu
  bukan penyimpanan, dan menjalankan perintah dalam hitungan detik.
- **Bukan pengunci yang tidak bisa dimatikan.** Pemilik akun Administrator
  yang paham Windows tetap bisa mengakhiri proses lewat Task Manager,
  menghapus tugas otomatisnya, atau mengubah registry tanpa memakai skrip ini.
  Sandi hanya menjaga perintah di dalam skrip.
- **Menutup jendela CMD** pada mode manual menghentikan pemantauan tanpa
  meminta sandi (pemblokiran USB tetap menyala).
- **Deteksi berdasarkan huruf drive baru, bukan khusus USB.** Drive jaringan
  dan DVD juga memicu alarm. HP yang tersambung lewat MTP tidak mendapat huruf
  drive, jadi tidak terdeteksi.
- **Whitelist berdasarkan huruf.** Jika flashdisk mendapat huruf yang ada di
  whitelist, alarm tidak berbunyi.
- **Polling 1 detik.** Drive yang dicolok dan dicabut dalam waktu kurang dari
  satu detik bisa terlewat. Selama layar merah tampil, pemantauan berhenti.
- **Jeda sandi memakai jam sistem**, sehingga bisa diakali dengan mengubah jam.
- **Alarm mengikuti volume dan mute sistem.** Jika laptop di-mute atau volumenya
  dikecilkan, alarm tidak terdengar (layar kunci tetap berjalan). Skrip tidak
  mengubah volume.
- **Pergantian ucapan bergantung pada deteksi layar terkunci.** Skrip menilai
  layar terkunci atau tidak lewat pemeriksaan desktop Windows. Jika deteksi ini
  keliru, petunjuk "sandi utama" dan "sandi kedua" bisa tertukar. Selain itu
  ucapan memakai PowerShell, jadi bisa gagal jika PowerShell dibatasi.
- **Tampilan bintang memperlihatkan panjang sandi** kepada orang yang melihat
  layarmu. Layar merah alarm juga hanya menyamarkan karakternya.
- **Akun Windows harus punya sandi.** Tanpa sandi, layar kunci tidak melindungi.
- **Hanya Windows.**

## Langkah darurat (lupa sandi atau pemblokiran tersangkut)

Dari CMD sebagai Administrator, tanpa memakai skrip:

```bat
:: batalkan pemblokiran USB
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" /v WriteProtect /t REG_DWORD /d 0 /f

:: batalkan mode otomatis
schtasks /End /TN USBAlarm
schtasks /Delete /TN USBAlarm /F

:: reset sandi (hapus file konfigurasi, lalu jalankan set-password lagi)
del "C:\ProgramData\USBAlarm\config.json"
```

Ini sekaligus menunjukkan batasan di atas: siapa pun dengan akses
Administrator bisa melakukannya.

## Mencoba dengan aman

Tes dengan flashdisk yang tidak penting. Urutan yang disarankan:

1. `python usb_lockdown.py help`, lalu `python usb_lockdown.py test-sound`
2. `python usb_lockdown.py manual`, buat sandi, lalu colok flashdisk.
3. Pastikan urutannya: ucapan peringatan, Windows terkunci, ucapan sandi utama
   di layar kunci, ucapan sandi kedua setelah login, lalu ucapan penutup
   setelah sandi kedua benar.
4. Coba menyalin file ke flashdisk: harus ditolak (disk write-protected).
5. Matikan alarm dengan sandi kedua, lalu Ctrl+C dan hentikan dengan kedua sandi.
6. Ulangi dengan `auto-on`, login ulang, dan cek `status`.

Hal yang bergantung pada versi Windows dan perlu diperiksa saat tes: apakah
pemblokiran berlaku untuk flashdisk yang sudah terpasang sebelum perlindungan
menyala (mungkin perlu dicabut dan dicolok ulang), apakah sandi Windows bisa
diverifikasi pada akunmu, dan apakah `auto-on` benar-benar berjalan setelah login.


