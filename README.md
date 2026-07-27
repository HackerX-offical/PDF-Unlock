# PDF Unlock

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Org](https://img.shields.io/badge/Org-HackerX%20Official-red.svg)

Recover forgotten passwords on encrypted PDFs and write unlocked copies.

**Project**: [PDF-Unlock](https://github.com/HackerX-offical/PDF-Unlock)  
**Organization**: [HackerX Official](https://github.com/HackerX-offical)

## Quick start

```bash
git clone https://github.com/HackerX-offical/PDF-Unlock.git
cd PDF-Unlock
./run_unlock.sh
```

Prompts for:

1. PDF file **or** folder  
2. Output folder  
3. Optional attack settings (Enter = defaults)  
4. Press Enter to run  

## Non-interactive

```bash
./run_unlock.sh -i /path/to/file.pdf -o /path/to/out --yes
./run_unlock.sh -i /path/to/folder -o /path/to/out --max-digits 8 --yes
```

## Attack order

1. Common passwords (bundled)  
2. Filename-derived candidates  
3. Optional custom `--wordlist`  
4. Date patterns (`DDMMYYYY` / `YYYYMMDD` / `DDMMYY`)  
5. Digit brute-force (default lengths 1–8)  
6. Optional short `a-z0-9` brute-force (`--max-alnum`)  
7. Reuse recovered passwords across files in the same run  

Then decrypts with `qpdf` if installed, otherwise `pikepdf`.

## Install (optional manual)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
unlock-pdf
```

## Notes

- Fastest on RC4 revision 2–3 PDFs. AES / newer revisions rely more on wordlists.  
- Strong long random passwords may not be recoverable in practical time.  
- Optional: `brew install qpdf` for faster decrypt.  
- Intended for recovering access to PDFs you own or are authorized to unlock.

## License

MIT License — Copyright (c) 2026 HackerX Official. See [LICENSE](LICENSE).

---

**HackerX Official** — Open Source Cybersecurity Tools
