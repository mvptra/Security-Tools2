"""USB Alarm: proteksi sederhana saat ada drive baru dicolok (khusus Windows).

Saat perlindungan aktif:
  - penyimpanan USB dibuat hanya-baca (registry WriteProtect), jadi data tidak
    bisa disalin ke flashdisk;
  - jika ada drive baru yang tidak ada di whitelist: alarm berbunyi dengan
    ucapan petunjuk (sirene alarm.wav jika ada, selain itu beep), laptop
    dikunci (kunci Windows asli), dan setelah login muncul layar merah yang
    baru hilang jika sandi kedua benar.

Ini tool pembelajaran, bukan pengganti keamanan sistem. Lihat README.md
untuk batasan lengkapnya. Jalankan `python usb_lockdown.py help` untuk daftar
perintah. Perintah yang mengubah pengaturan butuh CMD sebagai Administrator.
"""

import ctypes
import getpass
import hashlib
import hmac
import json
import os
import secrets
import string
import subprocess
import sys
import threading
import time
import wave
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

if os.name != "nt":
    raise SystemExit("Tool ini hanya untuk Windows.")

import msvcrt  # noqa: E402
import tkinter as tk  # noqa: E402
import winreg  # noqa: E402
import winsound  # noqa: E402

# --- KONFIGURASI ---
# Drive yang dianggap aman (biasanya drive internal). Tambahkan "D:" jika perlu.
WHITELIST_DRIVES = {"C:"}
POLL_INTERVAL = 1  # detik antar pengecekan drive

# Sirene: file "alarm.wav" di folder yang sama dengan skrip. Jika tidak ada
# (atau gagal diputar), dipakai beep.
ALARM_SOUND_NAME = "alarm.wav"

# Ucapan: urutan yang diputar adalah peringatan -> sandi_utama (selama layar
# terkunci) -> sandi_kedua (setelah login) -> selesai (sandi kedua benar).
# Secara bawaan ucapan dibuat dengan suara komputer Windows (System.Speech).
# Untuk memakai suaramu sendiri, taruh file suara_<kunci>.wav di folder skrip,
# misalnya suara_sandi_utama.wav. File itu menggantikan suara komputer.
VOICE_ENABLED = True
VOICE_PHRASES = {
    "peringatan": "Peringatan. Aktivitas mencurigakan terdeteksi.",
    "sandi_utama": "Silakan masukkan kata sandi utama.",
    "sandi_kedua": "Silakan masukkan kata sandi kedua.",
    "selesai": "Silakan melanjutkan aktivitas, Tuan.",
}
TTS_TIMEOUT = 30  # detik; batas waktu satu ucapan

MIN_PASSWORD_LEN = 8
PBKDF2_ITERATIONS = 200_000
FREE_ATTEMPTS = 3   # salah sandi berturut-turut sebelum mulai ada jeda
BASE_DELAY = 30     # detik; jeda berlipat dua tiap salah berikutnya
MAX_DELAY = 900     # detik; jeda maksimum (15 menit)

APP_NAME = "USBAlarm"
TASK_NAME = "USBAlarm"
MUTEX_NAME = "USBAlarmSingleInstance"
DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP_NAME
CONFIG_FILE = DATA_DIR / "config.json"
LOG_FILE = DATA_DIR / "events.log"
SCRIPT_PATH = Path(__file__).resolve()

REG_PATH = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
REG_VALUE = "WriteProtect"

LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0
ERROR_ALREADY_EXISTS = 183
SYNCHRONIZE = 0x00100000
DESKTOP_SWITCHDESKTOP = 0x0100

alarm_active = False
lock_window = None


# ---------------------------------------------------------------
# Log dan konfigurasi
# ---------------------------------------------------------------
def log_event(message):
    """Tambahkan satu baris ke events.log. Kegagalan menulis log diabaikan."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{stamp}  {message}\n")
    except OSError:
        pass


def load_config():
    """Baca config.json. Kembalikan None jika belum ada atau rusak."""
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_config(cfg):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


# ---------------------------------------------------------------
# Sandi: hash, batas percobaan, verifikasi
# ---------------------------------------------------------------
def make_hash(password):
    """Buat catatan hash PBKDF2-SHA256 dengan salt acak."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": PBKDF2_ITERATIONS}


def check_hash(password, record):
    salt = bytes.fromhex(record["salt"])
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, record["iterations"]
    )
    return hmac.compare_digest(digest.hex(), record["hash"])


def lockout_remaining(cfg):
    """Sisa detik jeda akibat terlalu banyak sandi salah (0 jika tidak ada)."""
    return max(0, int(cfg.get("locked_until", 0) - time.time()))


def register_failure(cfg):
    cfg["fails"] = cfg.get("fails", 0) + 1
    if cfg["fails"] >= FREE_ATTEMPTS:
        delay = min(BASE_DELAY * 2 ** (cfg["fails"] - FREE_ATTEMPTS), MAX_DELAY)
        cfg["locked_until"] = time.time() + delay
    save_config(cfg)


def register_success(cfg):
    cfg["fails"] = 0
    cfg["locked_until"] = 0
    save_config(cfg)


def read_password(prompt):
    """Baca sandi dan tampilkan '*' untuk tiap karakter yang diketik.

    Kalau input bukan terminal interaktif, pakai getpass biasa (tanpa tampilan).
    """
    if not sys.stdin.isatty():
        return getpass.getpass(prompt)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            return "".join(chars)
        if ch == "\x03":  # Ctrl+C
            sys.stdout.write("\n")
            raise KeyboardInterrupt
        if ch in ("\x00", "\xe0"):  # tombol khusus (panah, F1, dst.): abaikan
            msvcrt.getwch()
            continue
        if ch == "\b":
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        chars.append(ch)
        sys.stdout.write("*")
        sys.stdout.flush()


def verify_windows_password(password):
    """Tanya Windows apakah sandi ini benar untuk akun yang sedang login.

    Catatan: PIN atau sidik jari tidak diterima di sini. Sandi yang salah
    dihitung sebagai percobaan login gagal oleh Windows.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    ok = advapi32.LogonUserW(
        os.environ.get("USERNAME", ""),
        os.environ.get("USERDOMAIN", "."),
        password,
        LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(token),
    )
    if ok:
        kernel32.CloseHandle(token)
        return True
    return False


def create_password(label, must_differ_from=None):
    """Minta sandi baru dua kali (tampil sebagai '*'), minimal MIN_PASSWORD_LEN."""
    while True:
        first = read_password(f"{label} (minimal {MIN_PASSWORD_LEN} karakter): ")
        if len(first) < MIN_PASSWORD_LEN:
            print(f"Terlalu pendek, minimal {MIN_PASSWORD_LEN} karakter.")
            continue
        if must_differ_from is not None and first == must_differ_from:
            print("Sandi ini tidak boleh sama dengan sandi kedua.")
            continue
        if read_password("Ulangi sandi: ") != first:
            print("Sandi tidak sama, ulangi.")
            continue
        return first


def run_setup():
    """Buat sandi kedua dan tentukan sandi utama. Kembalikan config atau None."""
    print("=== Pengaturan sandi ===")
    second = create_password("Sandi kedua")

    print("\nSandi utama = sandi Windows akunmu. Mari diuji apakah bisa diverifikasi.")
    print("Catatan: sandi yang salah dihitung sebagai percobaan login gagal oleh Windows.")
    primary_mode = None
    primary_record = None
    while primary_mode is None:
        print("\n[1] Ketik sandi Windows untuk diuji")
        print("[2] Buat sandi utama terpisah di skrip (misalnya jika masuk pakai PIN)")
        print("[3] Batal")
        try:
            choice = input("Pilihan: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nDibatalkan.")
            return None
        if choice == "1":
            if verify_windows_password(read_password("Sandi Windows: ")):
                primary_mode = "windows"
            else:
                print("Tidak terverifikasi (salah ketik, pakai PIN, atau akun Microsoft?).")
        elif choice == "2":
            own = create_password(
                "Sandi utama (beda dari sandi kedua)", must_differ_from=second
            )
            primary_mode = "own"
            primary_record = make_hash(own)
        elif choice == "3":
            print("Dibatalkan.")
            return None

    cfg = {
        "version": 1,
        "second": make_hash(second),
        "primary_mode": primary_mode,
        "primary": primary_record,
        "fails": 0,
        "locked_until": 0,
    }
    save_config(cfg)
    log_event(f"Sandi dibuat (mode sandi utama: {primary_mode})")
    print("Sandi tersimpan (sebagai hash).")
    return cfg


def authenticate(action):
    """Minta sandi utama lalu sandi kedua. True hanya jika keduanya benar."""
    cfg = load_config()
    if not cfg:
        print("Sandi belum dibuat. Jalankan: python usb_lockdown.py set-password")
        return False

    remaining = lockout_remaining(cfg)
    if remaining:
        print(f"Terlalu banyak percobaan salah. Coba lagi {remaining} detik lagi.")
        return False

    label = "Sandi utama (sandi Windows)" if cfg["primary_mode"] == "windows" else "Sandi utama"
    try:
        primary = read_password(f"{label}: ")
        second = read_password("Sandi kedua: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return False

    # Kedua sandi selalu diperiksa supaya tidak ketahuan mana yang salah
    if cfg["primary_mode"] == "windows":
        primary_ok = verify_windows_password(primary)
    else:
        primary_ok = check_hash(primary, cfg["primary"])
    second_ok = check_hash(second, cfg["second"])

    if primary_ok and second_ok:
        register_success(cfg)
        log_event(f"Autentikasi berhasil untuk: {action}")
        return True

    register_failure(cfg)
    log_event(f"Autentikasi GAGAL untuk: {action}")
    remaining = lockout_remaining(cfg)
    if remaining:
        print(f"Sandi salah. Terkunci {remaining} detik.")
    else:
        print("Sandi salah.")
    return False


def verify_second(entered):
    """Dipakai layar alarm: hanya sandi kedua. Kembalikan (berhasil, pesan)."""
    cfg = load_config()
    if not cfg:
        return False, "Konfigurasi sandi tidak ditemukan."
    remaining = lockout_remaining(cfg)
    if remaining:
        return False, f"Terkunci, coba lagi {remaining} detik lagi."
    if check_hash(entered, cfg["second"]):
        register_success(cfg)
        return True, ""
    register_failure(cfg)
    remaining = lockout_remaining(cfg)
    if remaining:
        return False, f"Sandi salah. Terkunci {remaining} detik."
    return False, "Sandi salah."


# ---------------------------------------------------------------
# Windows: admin, registry, kunci, single instance
# ---------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin():
    if is_admin():
        return True
    print("Perintah ini butuh Administrator. Buka CMD dengan 'Run as administrator'.")
    return False


def set_write_protect(enabled):
    """Nyalakan/matikan mode hanya-baca untuk penyimpanan USB (butuh Administrator)."""
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, REG_VALUE, 0, winreg.REG_DWORD, 1 if enabled else 0)
    log_event(f"WriteProtect diatur ke {1 if enabled else 0}")


def get_write_protect():
    """Baca nilai WriteProtect: 1, 0, atau None jika belum diatur."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH) as key:
            value, _ = winreg.QueryValueEx(key, REG_VALUE)
            return int(value)
    except OSError:
        return None


def lock_workstation():
    """Kunci Windows (sama seperti Win+L)."""
    try:
        ctypes.windll.user32.LockWorkStation()
    except Exception as e:
        log_event(f"Gagal mengunci Windows: {e}")


def already_running():
    """True jika instance lain sudah berjalan. Mutex sengaja dibiarkan terbuka."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    already = ctypes.get_last_error() == ERROR_ALREADY_EXISTS
    if already and handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    return already


def is_running():
    """Cek apakah pemantauan sedang berjalan (tanpa membuat mutex baru)."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenMutexW.restype = ctypes.c_void_p
    handle = kernel32.OpenMutexW(SYNCHRONIZE, False, MUTEX_NAME)
    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return True
    return False


def run_cmd(args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace")


# ---------------------------------------------------------------
# Alarm dan layar merah
# ---------------------------------------------------------------
def find_alarm_sound():
    """Kembalikan Path alarm.wav jika ada di folder skrip, selain itu None."""
    path = SCRIPT_PATH.parent / ALARM_SOUND_NAME
    return path if path.is_file() else None


def wav_duration(path):
    """Durasi file .wav dalam detik, atau None jika tidak terbaca."""
    try:
        with wave.open(str(path), "rb") as w:
            return w.getnframes() / w.getframerate()
    except Exception:
        return None


def wait_playing(seconds, respect_alarm=True):
    """Tunggu `seconds` detik; berhenti lebih awal jika alarm dimatikan."""
    end = time.time() + seconds
    while time.time() < end and (alarm_active or not respect_alarm):
        time.sleep(0.05)


def play_wav_blocking(path, respect_alarm=True):
    """Putar .wav sampai selesai (atau alarm dimatikan). False jika gagal."""
    duration = wav_duration(path)
    if duration is None:
        return False
    try:
        winsound.PlaySound(str(path), winsound.SND_FILENAME | winsound.SND_ASYNC)
        wait_playing(duration + 0.2, respect_alarm)
        winsound.PlaySound(None, winsound.SND_PURGE)
    except Exception as e:
        log_event(f"Gagal memutar {Path(path).name}: {e}")
        return False
    return True


def play_siren():
    """Putar sirene sekali (alarm.wav), atau beep ~2 detik jika file tidak ada."""
    sound = find_alarm_sound()
    if sound is not None and play_wav_blocking(sound):
        return
    nada = [2500, 1500]
    end = time.time() + 2
    i = 0
    while alarm_active and time.time() < end:
        winsound.Beep(nada[i % 2], 150)
        i += 1


TTS_SCRIPT = (
    "Add-Type -AssemblyName System.Speech; "
    "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
    "$v = $s.GetInstalledVoices() | Where-Object "
    "{ $_.Enabled -and $_.VoiceInfo.Culture.Name -like 'id*' } "
    "| Select-Object -First 1; "
    "if ($v) { $s.SelectVoice($v.VoiceInfo.Name) }; "
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "Write-Output $s.Voice.Name; "
    "$s.Speak($env:USBALARM_TEXT)"
)


def speak_tts(text, respect_alarm=True):
    """Ucapkan teks dengan suara komputer Windows. Kembalikan nama suara atau None."""
    env = dict(os.environ, USBALARM_TEXT=text)
    try:
        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", TTS_SCRIPT],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as e:
        log_event(f"Gagal menjalankan PowerShell untuk ucapan: {e}")
        return None

    deadline = time.time() + TTS_TIMEOUT
    while proc.poll() is None and time.time() < deadline and (alarm_active or not respect_alarm):
        time.sleep(0.05)
    if proc.poll() is None:
        proc.terminate()
    try:
        out, _ = proc.communicate(timeout=3)
    except Exception:
        proc.kill()
        return None
    return (out or "").strip().splitlines()[0] if (out or "").strip() else None


def speak(key, respect_alarm=True):
    """Ucapkan kalimat `key`. Kembalikan keterangan sumber suara, atau None."""
    if not VOICE_ENABLED:
        return None
    custom = SCRIPT_PATH.parent / f"suara_{key}.wav"
    if custom.is_file() and play_wav_blocking(custom, respect_alarm):
        return f"file {custom.name}"
    voice = speak_tts(VOICE_PHRASES[key], respect_alarm)
    if voice is None:
        log_event(f"Ucapan '{key}' gagal diputar.")
        return None
    return f"suara komputer ({voice})"


def is_workstation_locked():
    """True jika layar Windows sedang terkunci. False jika tidak (atau tidak pasti)."""
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.OpenDesktopW.restype = ctypes.c_void_p
        user32.OpenDesktopW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32,
        ]
        user32.SwitchDesktop.argtypes = [ctypes.c_void_p]
        user32.CloseDesktop.argtypes = [ctypes.c_void_p]
        desktop = user32.OpenDesktopW("Default", 0, False, DESKTOP_SWITCHDESKTOP)
        if not desktop:
            return False
        try:
            return not bool(user32.SwitchDesktop(desktop))
        finally:
            user32.CloseDesktop(desktop)
    except Exception as e:
        log_event(f"Gagal memeriksa status kunci layar: {e}")
        return False


announce_thread = None


def announce_loop():
    """Urutan suara: peringatan, lalu bergantian sirene dan petunjuk sandi."""
    try:
        speak("peringatan")
        while alarm_active:
            play_siren()
            if not alarm_active:
                break
            speak("sandi_utama" if is_workstation_locked() else "sandi_kedua")
    except Exception as e:
        log_event(f"Urutan suara berhenti karena kesalahan: {e}")


def start_alarm():
    """Mulai urutan suara alarm di thread terpisah."""
    global alarm_active, announce_thread
    alarm_active = True
    announce_thread = threading.Thread(target=announce_loop, daemon=True)
    announce_thread.start()


def stop_alarm(final_phrase=True):
    """Hentikan alarm, lalu ucapkan kalimat penutup di thread terpisah."""
    global alarm_active, announce_thread
    alarm_active = False
    if announce_thread is not None:
        announce_thread.join(timeout=5)
        announce_thread = None
    try:
        winsound.PlaySound(None, winsound.SND_PURGE)
    except Exception as e:
        log_event(f"Gagal menghentikan suara: {e}")
    if final_phrase:
        threading.Thread(target=speak, args=("selesai", False), daemon=True).start()


def trigger_lockdown(drive_name):
    """Alarm + kunci Windows + layar merah sampai sandi kedua benar."""
    global alarm_active, lock_window
    if alarm_active:
        return

    alarm_active = True
    log_event(f"Drive baru terdeteksi: {drive_name}. Alarm dan kunci Windows dijalankan.")
    start_alarm()
    lock_workstation()

    lock_window = tk.Tk()
    lock_window.attributes("-fullscreen", True)
    lock_window.attributes("-topmost", True)
    lock_window.configure(bg="darkred")
    lock_window.protocol("WM_DELETE_WINDOW", lambda: None)

    tk.Label(
        lock_window,
        text="PERINGATAN: DRIVE BARU TERDETEKSI",
        font=("Arial", 28, "bold"),
        fg="white",
        bg="darkred",
    ).pack(pady=100)

    tk.Label(
        lock_window,
        text=f"Drive baru ({drive_name}) terdeteksi.\n"
             "Masukkan sandi kedua untuk mematikan alarm.",
        font=("Arial", 16),
        fg="yellow",
        bg="darkred",
    ).pack(pady=20)

    frame = tk.Frame(lock_window, bg="darkred")
    frame.pack(pady=40)
    tk.Label(
        frame, text="Sandi kedua:", font=("Arial", 14, "bold"),
        fg="white", bg="darkred",
    ).pack(side=tk.LEFT, padx=10)
    entry = tk.Entry(frame, show="*", font=("Arial", 16), width=25)
    entry.pack(side=tk.LEFT, padx=10)
    entry.focus()

    status_var = tk.StringVar()
    tk.Label(
        lock_window, textvariable=status_var, font=("Arial", 14),
        fg="white", bg="darkred",
    ).pack(pady=10)

    def submit(event=None):
        ok, message = verify_second(entry.get())
        if ok:
            stop_alarm()
            log_event("Alarm dimatikan dengan sandi kedua.")
            lock_window.destroy()
        else:
            status_var.set(message)
            entry.delete(0, tk.END)

    tk.Button(
        lock_window, text="MATIKAN ALARM", font=("Arial", 14, "bold"),
        bg="black", fg="white", command=submit,
    ).pack(pady=20)
    lock_window.bind("<Return>", submit)
    lock_window.mainloop()


# ---------------------------------------------------------------
# Pemantauan drive
# ---------------------------------------------------------------
def get_active_drives():
    """Daftar huruf drive yang sedang terpasang, misalnya ['C:', 'E:']."""
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:"
        if os.path.exists(drive + "\\"):
            drives.append(drive)
    return drives


def monitor_loop(known_drives):
    """Pantau drive baru tanpa henti. known_drives diperbarui di tempat."""
    while True:
        current = set(get_active_drives())
        for drive in sorted(current - known_drives):
            if drive not in WHITELIST_DRIVES:
                trigger_lockdown(drive)
                break
        known_drives.clear()
        known_drives.update(current)
        time.sleep(POLL_INTERVAL)


def run_protection(interactive):
    """Nyalakan perlindungan. interactive=True untuk mode manual (di CMD)."""
    if already_running():
        message = "Perlindungan sudah berjalan (mungkin dari mode otomatis)."
        print(message)
        log_event(message)
        return 1

    cfg = load_config()
    if not cfg:
        if not interactive:
            log_event("Layanan berhenti: sandi belum dibuat.")
            return 1
        cfg = run_setup()
        if not cfg:
            return 1

    try:
        set_write_protect(True)
    except OSError as e:
        message = f"Gagal mengaktifkan pemblokiran USB: {e}"
        print(message)
        log_event(message)
        return 1

    known = set(get_active_drives())
    log_event(f"Perlindungan aktif ({'manual' if interactive else 'otomatis'}). "
              f"Drive awal: {sorted(known)}")

    if not interactive:
        monitor_loop(known)
        return 0

    print("Perlindungan aktif: penyimpanan USB hanya-baca, drive baru memicu alarm.")
    print("Untuk berhenti: tekan Ctrl+C lalu masukkan sandi utama dan sandi kedua.")
    while True:
        try:
            monitor_loop(known)
        except KeyboardInterrupt:
            print("\nMenghentikan perlindungan? Masukkan sandi.")
            if authenticate("hentikan mode manual"):
                set_write_protect(False)
                print("Perlindungan dihentikan dan pemblokiran USB dibatalkan.")
                return 0
            print("Perlindungan tetap aktif.")


# ---------------------------------------------------------------
# Mode otomatis (Task Scheduler)
# ---------------------------------------------------------------
def build_task_xml(exe, script, user):
    """Definisi tugas: jalan saat login, hak tertinggi, tanpa batas waktu/baterai."""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{xml_escape(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{xml_escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{xml_escape(str(exe))}</Command>
      <Arguments>{xml_escape('"' + str(script) + '" service')}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


# ---------------------------------------------------------------
# Perintah CLI
# ---------------------------------------------------------------
def cmd_help():
    print(
        "USB Alarm: proteksi drive baru untuk Windows\n"
        "\n"
        "Pemakaian: python usb_lockdown.py <perintah>\n"
        "\n"
        "Perintah:\n"
        "  help          Tampilkan daftar perintah ini\n"
        "  manual        Nyalakan perlindungan di CMD ini (aktif selama jendela terbuka)\n"
        "  auto-on       Daftarkan agar menyala sendiri tiap Windows login\n"
        "  auto-off      Batalkan penyalaan otomatis (butuh 2 sandi)\n"
        "  status        Lihat status perlindungan, pemblokiran, dan mode otomatis\n"
        "  test-sound    Putar sirene dan semua ucapan untuk menguji (tanpa mengunci)\n"
        "  unblock       Batalkan pemblokiran USB hanya-baca (butuh 2 sandi)\n"
        "  set-password  Buat atau ganti sandi (butuh 2 sandi jika sudah ada)\n"
        "\n"
        "Perintah selain help, status, dan test-sound butuh CMD sebagai Administrator.\n"
        "Sandi utama = sandi Windows akunmu. Sandi kedua = dibuat lewat skrip ini.\n"
    )
    return 0


def cmd_test_sound():
    """Putar sirene dan semua ucapan sebagai uji, tanpa mengunci apa pun."""
    global alarm_active
    sound = find_alarm_sound()
    print(f"Sirene : {sound if sound else 'alarm.wav tidak ditemukan, memakai beep'}")
    print(f"Ucapan : {'aktif' if VOICE_ENABLED else 'dimatikan (VOICE_ENABLED = False)'}")
    alarm_active = True
    try:
        print("\n1. Sirene...")
        play_siren()
        if VOICE_ENABLED:
            for number, key in enumerate(VOICE_PHRASES, start=2):
                print(f"{number}. {key}: \"{VOICE_PHRASES[key]}\"")
                source = speak(key)
                print(f"   -> {source if source else 'GAGAL diputar (lihat events.log)'}")
    finally:
        alarm_active = False
        try:
            winsound.PlaySound(None, winsound.SND_PURGE)
        except Exception:
            pass
    print("\nSelesai.")
    return 0


def cmd_manual():
    if not require_admin():
        return 1
    return run_protection(interactive=True)


def cmd_service():
    """Dipanggil Task Scheduler saat login. Tidak interaktif."""
    if not is_admin():
        log_event("Layanan berhenti: tidak berjalan sebagai Administrator.")
        return 1
    return run_protection(interactive=False)


def cmd_auto_on():
    if not require_admin():
        return 1
    if not load_config() and not run_setup():
        return 1

    pythonw = Path(sys.executable).with_name("pythonw.exe")
    exe = pythonw if pythonw.exists() else Path(sys.executable)
    user = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}"

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    xml_path = DATA_DIR / "task.xml"
    with open(xml_path, "w", encoding="utf-16") as f:
        f.write(build_task_xml(exe, SCRIPT_PATH, user))

    result = run_cmd(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"])
    try:
        xml_path.unlink()
    except OSError:
        pass
    if result.returncode != 0:
        print("Gagal mendaftarkan mode otomatis:")
        print(result.stdout.strip() or result.stderr.strip())
        return 1

    log_event("Mode otomatis didaftarkan.")
    print("Mode otomatis aktif: perlindungan menyala sendiri setiap kali login.")
    print(f"Skrip dipanggil dari: {SCRIPT_PATH}")
    print("Jangan pindahkan atau hapus file ini, atau penyalaan otomatis akan gagal.")
    return 0


def cmd_auto_off():
    if not require_admin():
        return 1
    if not authenticate("auto-off"):
        return 1
    run_cmd(["schtasks", "/End", "/TN", TASK_NAME])
    result = run_cmd(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    if result.returncode != 0:
        print("Mode otomatis tidak ditemukan atau gagal dihapus:")
        print(result.stdout.strip() or result.stderr.strip())
        return 1
    log_event("Mode otomatis dibatalkan.")
    print("Mode otomatis dibatalkan. File skrip tetap ada.")
    print("Pemblokiran USB tetap menyala sampai kamu menjalankan: unblock")
    return 0


def cmd_unblock():
    if not require_admin():
        return 1
    if not authenticate("unblock"):
        return 1
    try:
        set_write_protect(False)
    except OSError as e:
        print(f"Gagal membatalkan pemblokiran: {e}")
        return 1
    print("Pemblokiran USB dibatalkan.")
    if is_running():
        print("Catatan: pemantauan masih berjalan. Hentikan dulu (manual: Ctrl+C + sandi,")
        print("otomatis: auto-off) kalau tidak ingin ia mengaktifkan blokir lagi nanti.")
    return 0


def cmd_set_password():
    if not require_admin():
        return 1
    if load_config() and not authenticate("set-password"):
        return 1
    return 0 if run_setup() else 1


def cmd_status():
    print(f"Administrator          : {'ya' if is_admin() else 'tidak'}")

    cfg = load_config()
    if cfg:
        print(f"Sandi                  : sudah dibuat (sandi utama: {cfg['primary_mode']})")
        remaining = lockout_remaining(cfg)
        if remaining:
            print(f"Jeda sandi salah       : {remaining} detik tersisa")
    else:
        print("Sandi                  : belum dibuat (jalankan: set-password)")

    wp = get_write_protect()
    names = {1: "AKTIF (hanya-baca)", 0: "nonaktif", None: "belum pernah diatur"}
    print(f"Pemblokiran USB        : {names.get(wp, str(wp))}")

    registered = run_cmd(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0
    print(f"Mode otomatis          : {'terdaftar' if registered else 'tidak terdaftar'}")
    print(f"Pemantauan berjalan    : {'ya' if is_running() else 'tidak'}")
    print(f"Log kejadian           : {LOG_FILE}")
    return 0


COMMANDS = {
    "help": cmd_help,
    "manual": cmd_manual,
    "service": cmd_service,  # internal, dipanggil Task Scheduler
    "auto-on": cmd_auto_on,
    "auto-off": cmd_auto_off,
    "status": cmd_status,
    "test-sound": cmd_test_sound,
    "unblock": cmd_unblock,
    "set-password": cmd_set_password,
}


def main(argv):
    command = argv[1].lower() if len(argv) > 1 else "help"
    if command in ("-h", "--help", "/?"):
        command = "help"
    handler = COMMANDS.get(command)
    if handler is None:
        print(f"Perintah tidak dikenal: {command}\n")
        cmd_help()
        return 1
    try:
        return handler() or 0
    except KeyboardInterrupt:
        print("\nDibatalkan.")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
