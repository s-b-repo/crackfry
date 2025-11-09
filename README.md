# whyfly  
Linux Wi-Fi brute-forcer for WPA1/2/3 PSK and SAE (WPA3) networks.

## What it does  
- Scans the air for every access-point in range.  
- Detects security type automatically: WPA3-SAE, WPA2-PSK, WPA1-PSK.  
- Reads password lists in **plain text, gz, bz2, xz, 7z, zip, .hccapx, hashcat potfile, john potfile**, … without unpacking the whole file to disk.  
- Streams the word-list in constant RAM; each worker keeps only one password in memory.  
- Runs **fully asynchronous**: no blocking I/O, no global interpreter lock contention.  
- Spawns one wpa_supplicant instance per CPU core; each tries its share of passwords against every network.  
- Writes every successful (SSID, BSSID, password) tuple to `./cracked.l` immediately, so you can `tail -f` it.  
- Cleans up on Ctrl-C: terminates supplicants, removes control sockets, closes fifos.

## Limitations  
- Linux only (relies on `iw` and `wpa_supplicant`).  
- Must be started as root (scanning and reconfiguring the interface requires CAP_NET_ADMIN).  
- Only attacks PSK/SAE; no support for enterprise (EAP) networks.  
- Speed is limited by how fast wpa_supplicant can complete the 4-way handshake or SAE commit; this is **not** a GPU-based attack.  
- Decompression uses the shell (`zcat`, `7z`, …); make sure those tools are installed for the formats you intend to use.

## Build / install  
1. Install system utilities  
   ```
   sudo apt update
   sudo apt install iw wpasupplicant p7zip-full gzip bzip2 xz-utils unzip
   ```  
   (Adjust the package manager for non-Debian distributions.)

2. Create a Python ≥ 3.9 virtual environment  
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install -U pip
   ```

3. Install the minimal Python dependencies  
   ```
   pip install aiofiles
   # optional, only if you want .7z support
   pip install py7zr
   ```

4. Clone or simply download the single-file script  



## Quick start  
Scan and attack every new network in range:  
```
sudo ./whyfly.py rockyou.txt.gz
```

Use a different wireless interface and 8 parallel workers:  
```
sudo ./whyfly.py -i wlp2s0 -w 8 passwords.zip
```

Resume / add more passwords later – already cracked SSIDs are skipped automatically.

## Output  
While running:  
```
[12:34:56.789] INFO  4 APs to test
[12:34:57.123] INFO  CRACKED → myHome  |  sunshine123
```
When you stop you will find:  
```
{"ssid":"myHome","bssid":"aa:bb:cc:dd:ee:ff","password":"sunshine123","time":1699542899}
```
in `cracked.l`, one line per network.

## Troubleshooting  
- **“Must run as root”** – self explanatory.  
- **“worker X could not start supplicant”** – check that `wpa_supplicant` is installed and the interface is not managed by NetworkManager (`nmcli device set wlan0 managed no`).  
- **No APs found** – verify the interface is up and supports 2.4 / 5 GHz scanning (`iw dev wlan0 scan`).  
- **Very slow** – increase workers (`-w`) or shorten handshake timeout in the script; remember that SAE is slower than WPA2.

