import os
import time
import string
import threading
import tkinter as tk
from tkinter import messagebox
import winsound

# --- KONFIGURASI ---
WHITELIST_DRIVES = ["C:"]  # Drive internal laptop lu (ubah jika ada D:)
SECOND_PASSWORD = "rahasia_banget_bro"  # Ganti dengan sandi kedua lu!

# Catatan: pygame DIHAPUS dari versi ini supaya gak perlu install
# library tambahan - winsound (bawaan Python di Windows) sudah
# cukup buat bikin alarm berisik.

alarm_active = False
lock_window = None


def play_alarm():
    """
    Memutar suara alarm berisik secara beruntun pakai winsound bawaan.
    Durasi tiap beep dibikin pendek (150ms) dan status alarm_active
    dicek di antara tiap beep, supaya begitu password benar, suara
    langsung berhenti nyaris instan (bukan nunggu 1 detik lagi).
    """
    nada = [2500, 1500]  # dua nada bergantian biar kedengaran alarm
    i = 0
    while alarm_active:
        winsound.Beep(nada[i % 2], 150)
        i += 1


def trigger_lockdown(drive_name):
    global alarm_active, lock_window
    if alarm_active:
        return  # Kalau sudah aktif, jangan ditumpuk

    alarm_active = True

    # Jalankan alarm di thread terpisah biar tidak macet
    t = threading.Thread(target=play_alarm)
    t.daemon = True
    t.start()

    # Buat Tampilan Layar Merah Penuh (Fullscreen Lockdown)
    lock_window = tk.Tk()
    lock_window.attributes("-fullscreen", True)
    lock_window.attributes("-topmost", True)
    lock_window.configure(bg="darkred")

    # Mencegah tombol Alt+F4 / Close window
    lock_window.protocol("WM_DELETE_WINDOW", lambda: None)

    title_label = tk.Label(
        lock_window,
        text="PERINGATAN: ANCAMAN KEAMANAN TERDETEKSI!",
        font=("Arial", 28, "bold"),
        fg="white",
        bg="darkred",
    )
    title_label.pack(pady=100)

    sub_label = tk.Label(
        lock_window,
        text=f"Perangkat USB asing ({drive_name}) terdeteksi menyolok!\n"
             "Sistem dikunci otomatis. Masukkan sandi kedua untuk membuka.",
        font=("Arial", 16),
        fg="yellow",
        bg="darkred",
    )
    sub_label.pack(pady=20)

    pass_frame = tk.Frame(lock_window, bg="darkred")
    pass_frame.pack(pady=40)

    pass_label = tk.Label(pass_frame, text="Sandi Kedua:", font=("Arial", 14, "bold"),
                           fg="white", bg="darkred")
    pass_label.pack(side=tk.LEFT, padx=10)

    pass_entry = tk.Entry(pass_frame, show="*", font=("Arial", 16), width=25)
    pass_entry.pack(side=tk.LEFT, padx=10)
    pass_entry.focus()

    def verify_password(event=None):
        global alarm_active, lock_window
        entered_pass = pass_entry.get()
        if entered_pass == SECOND_PASSWORD:
            alarm_active = False
            lock_window.destroy()
        else:
            messagebox.showerror("Akses Ditolak", "Sandi salah! Laptop tetap dikunci.")
            pass_entry.delete(0, tk.END)

    btn_unlock = tk.Button(lock_window, text="BUKA KUNCI", font=("Arial", 14, "bold"),
                            bg="black", fg="white", command=verify_password)
    btn_unlock.pack(pady=20)

    lock_window.bind("<Return>", verify_password)

    lock_window.mainloop()


def get_active_drives():
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:"
        if os.path.exists(drive + "\\"):
            drives.append(drive)
    return drives


def monitor_usb():
    print("Sistem Alarm USB Lockdown Aktif... (jangan tutup jendela ini)")
    initial_drives = set(get_active_drives())
    print(f"Drive awal terdeteksi: {initial_drives}")

    while True:
        current_drives = set(get_active_drives())
        new_drives = current_drives - initial_drives

        for drive in new_drives:
            if drive not in WHITELIST_DRIVES:
                print(f"Drive baru terdeteksi: {drive} -> trigger lockdown")
                trigger_lockdown(drive)
                break

        initial_drives = current_drives
        time.sleep(1)


# INI BAGIAN YANG HILANG DI VERSI SEBELUMNYA -
# tanpa baris ini, monitor_usb() gak akan pernah jalan.
if __name__ == "__main__":
    monitor_usb()
