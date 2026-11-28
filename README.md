# ZeroExtract 🚀

**Zero-Extra-Space In-Place Archive Extractor for Large Games & Datasets**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-250%20Passed%20(100%25)-brightgreen.svg)]()
[![Platform: Windows & Linux](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()

[Website & Direct Downloads](https://yadavharshit448-png.github.io/ZeroExtract/) &bull; [GitHub Releases](https://github.com/yadavharshit448-png/ZeroExtract/releases/latest) &bull; [Sponsor / Commercial Inquiry](https://yadavharshit448-png.github.io/ZeroExtract/#support)

---

## 🎮 The Problem: The "Double Space" Dilemma

When you download a **50 GB game archive** from the internet and have **55 GB of free disk space**, traditional extraction software (WinRAR, 7-Zip, Windows Explorer, unar) fails:

```
[Available Disk Space: 55 GB]
1. Download 50 GB game archive:      [■■■■■■■■■■] (50 GB used, 5 GB free)
2. Try extracting the game:          ❌ ERROR: Not enough disk space!
                                      Extraction requires an additional 50 GB.
                                      Total needed: 100 GB.
```

Standard extractors unpack all files to disk first before you can delete the original archive, requiring **2× the archive size** (100 GB). If you don't have that extra space, you simply cannot play the game.

---

## 💡 The Solution: ZeroExtract

**ZeroExtract** solves this problem by **dynamically and progressively reclaiming physical disk space** from the archive as files are extracted. As member files are decompressed onto your drive, the corresponding blocks in the source archive are immediately freed, keeping your peak disk footprint within a few hundred megabytes of the original archive size:

```
[Available Disk Space: 55 GB]
1. Download 50 GB game archive:      [■■■■■■■■■■] (50 GB used, 5 GB free)
2. Run ZeroExtract:
   - Extract Game_Asset_01 (5 GB)    -> Archive shrunk by 5 GB  (5 GB free maintained)
   - Extract Game_Asset_02 (10 GB)   -> Archive shrunk by 10 GB (5 GB free maintained)
   - ...
3. Finish: Game is fully playable, original archive safely deallocated.
   Total disk space needed: ~50 GB!
```

---

## ⚙️ How It Works (Technical Architecture)

ZeroExtract utilizes a multi-layered filesystem and compression pipeline:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ZeroExtract CLI Engine                          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌───────────────────────────────┐         ┌───────────────────────────────┐
│     Preflight Shield (F8)     │         │   Transaction Journal (F10)   │
│ 0-byte non-destructive scan   │         │ 2-phase commit state tracking │
│ Checks CRCs & headers first   │         │ Crash recovery & resumption   │
└──────────────┬────────────────┘         └──────────────┬────────────────┘
               │                                         │
               ▼                                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Decompression Pipeline                         │
├───────────────────────────────────┬────────────────────────────────────┤
│ Reverse Tail Truncation (F2, F5)  │ Multi-Volume Stream Deletion (F3)  │
│ Unpacks entries tail-to-head,     │ Unlinks .z01, .part1.rar, .001     │
│ physically truncates archive file │ slices immediately upon completion │
├───────────────────────────────────┴────────────────────────────────────┤
│ Chunked Sparse Deallocation (F1, F7)                                   │
│ Win32 FSCTL_SET_ZERO_DATA / FSCTL_SET_SPARSE 64KB hole punching        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    Two-Phase Commit Atomic Writer (F9)                 │
│ Writes to .unpack_part -> Verifies CRC32 -> os.replace atomic rename   │
│ Zero partial, broken, or corrupt files left on disk if interrupted     │
└────────────────────────────────────────────────────────────────────────┘
```

1. **0-Byte Preflight Verification Shield**: Before modifying or truncating a single byte of your archive, ZeroExtract scans Central Directories, headers, and member CRCs in memory. If corruption, truncated downloads, or bad CRCs are detected, it **aborts immediately** with an informative report, leaving your archive 100% untouched.
2. **Reverse Tail-First Truncation**: Standard archives store files head-to-tail. ZeroExtract parses the Central Directory and extracts entries in **reverse order (tail-to-head)**. As each entry finishes, the source file is physically truncated from the tail, immediately returning free drive clusters to Windows NTFS.
3. **NTFS Sparse Hole-Punching**: For huge monolithic files (e.g., 20 GB `.pak` or `.dat` files) stored inside archives, ZeroExtract issues native Win32 `FSCTL_SET_SPARSE` and `FSCTL_SET_ZERO_DATA` controls, punching 64KB cluster-aligned zero holes directly into the source archive while streaming the decompressed payload.
4. **Multi-Part Volume Unlinking**: Automatically detects split archives (`.z01`...`.zip`, `.part1.rar`...`.partN.rar`, `.001`...`.00N`) and progressively unlinks each completed slice file the instant all its contained members are written to disk.
5. **Crash-Safe 2-Phase Commit Journal**: Extraction progress is logged to `.unpack_journal.json`. If a power cut or system crash occurs midway, running ZeroExtract again seamlessly picks up where it left off without starting over.
6. **Atomic File Staging**: Output files are written to `.unpack_part` temporary files and committed atomically via `os.replace` only after CRC32 verification passes. If extraction is aborted, no corrupt or half-written game files remain.

---

## 📥 Download & Installation

### Option 1: Windows Standalone App (Recommended — No Python Needed)
1. Download the latest **`zeroextract.exe`** from the [**GitHub Releases**](https://github.com/yadavharshit448-png/zeroextract/releases) page.
2. Double-click or run `zeroextract.exe --gui` for the desktop interface, or extract directly from terminal:
   ```cmd
   zeroextract.exe "D:\Downloads\GameArchive.zip"
   ```
3. *(Optional)* Download the repo/scripts and double-click **`install_context_menu.bat`** to add **"Extract with ZeroExtract (No Extra Space)"** to your Windows Explorer right-click menu for `.zip`, `.rar`, and `.7z` files.

### Option 2: Install from Source (Python 3.9+)
Clone or download this repository, then install with pip:
```bash
git clone https://github.com/yadavharshit448-png/zeroextract.git
cd zeroextract
pip install -e .
```

### Option 3: Portable / No Installation Needed
Run directly with Python:
```bash
python -m zeroextract --help
```
or launch the desktop GUI:
```bash
python -m zeroextract --gui
```

---

## 🚀 Usage

### 1. Basic Extraction
Extract an archive directly into a folder next to it:
```bash
zeroextract "D:\Downloads\CyberpunkGame.zip"
```

### 2. Custom Output Directory
Specify where the extracted game should be placed:
```bash
zeroextract "D:\Downloads\EldenRing.zip" -o "D:\Games\EldenRing"
```

### 3. Drag-and-Drop (Windows Explorer)
Simply drag your game archive (`.zip`, `.zip.001`, `.part1.rar`, `.z01`) directly onto `zeroextract.bat` in Windows Explorer!

### 4. Dry-Run Simulation
Inspect an archive, calculate uncompressed payload size, and verify disk space savings without writing anything:
```bash
zeroextract "D:\Downloads\GameArchive.zip" --dry-run
```

### 5. Multi-Part Split Archives
Provide either the first part or the main `.zip` file — ZeroExtract automatically discovers all companion parts in sequence:
```bash
zeroextract "D:\Downloads\BigGame.part1.rar" -o "D:\Games\BigGame"
# or
zeroextract "D:\Downloads\BigGame.zip.001" -o "D:\Games\BigGame"
# or
zeroextract "D:\Downloads\BigGame.zip" -o "D:\Games\BigGame"
```

---

## 🛠️ Command-Line Options

| Flag | Short | Description |
|---|---|---|
| `--output-dir` | `-o` | Destination directory for extracted game files |
| `--gui` | | Launch the interactive desktop Graphical User Interface |
| `--dry-run` | | Simulate extraction without modifying files or shrinking archive |
| `--no-verify` | | Skip 0-byte preflight verification (start extracting immediately) |
| `--min-headroom` | | Minimum free disk space cushion in bytes (default: `10485760` / 10 MB) |
| `--chunk-size` | | I/O streaming buffer and sparse cluster chunk size (default: `1048576` / 1 MB) |
| `--quiet` | `-q` | Suppress interactive progress bar (ideal for scripts/batch) |
| `--verbose` | `-v` | Output detailed diagnostics |
| `--version` | | Display ZeroExtract version |
| `--help` | `-h` | Display usage and help message |

---

## 🛡️ Corruption & Crash Safeguards

| Failure Mode | How ZeroExtract Protects Your Data |
|---|---|
| **Corrupted Download / Bad CRC** | Preflight Shield validates member CRCs before extraction. Aborts with 0 bytes extracted and 0 bytes truncated from archive. |
| **Power Cut / Crash Midway** | `.unpack_journal.json` tracks completed files. Re-running the command resumes immediately from the next pending member. |
| **Aborted Mid-File** | Active files are written to `.unpack_part`. On abort, `.unpack_part` is cleaned up so no broken files are left in the game folder. |
| **Low Disk Headroom** | Headroom monitor checks free space continuously. If free disk space drops below `--min-headroom`, extraction safely pauses/aborts before disk fills. |
| **Malicious Zip Slip** | Path traversal attacks (`../../evil.dll`) are sanitized and rejected with `PathTraversalError`. |

---

## 🧪 Comprehensive Verification Suite

ZeroExtract includes an extensive, 4-tier test suite covering 250 test cases:

```bash
# Run all unit tests
pytest tests/unit

# Run full 4-tier E2E test suite (feature coverage, boundary cases, combinations, real-world)
python tests/run_e2e_tests.py --tier all
```

**Test Coverage Results:**
- **Unit Tests**: 75 / 75 Passed (100%)
- **Tier 1 (Feature Coverage F1–F14)**: 70 / 70 Passed (100%)
- **Tier 2 (Boundary & Corner Cases)**: 73 / 73 Passed (100%)
- **Tier 3 (Subsystem Combinations)**: 18 / 18 Passed (100%)
- **Tier 4 (Real-World Scenarios)**: 14 / 14 Passed (100%)
- **Total**: **250 / 250 Passed** (Zero failures, zero skipped)

---

## 📦 Deployment & Distribution

### 1. Standalone Windows Executable (`zeroextract.exe`)
Build a single self-contained executable that users can run without installing Python:
```cmd
build_exe.bat
```
The output file will be in `dist\zeroextract.exe`.

### 2. Windows Explorer Right-Click Integration
Double-click `install_context_menu.bat` to add **"Extract with ZeroExtract (No Extra Space)"** to your Windows right-click menu. To remove it later, run `uninstall_context_menu.bat`.

### 3. GitHub Releases (Automated CI/CD)
The repository includes `.github/workflows/release.yml`. Pushing a tag (`git tag v0.1.0 && git push origin v0.1.0`) automatically triggers GitHub Actions to run all 247 tests, build `zeroextract.exe`, build wheels, and publish a complete GitHub Release.

### 4. PyPI Deployment
To publish to the Python Package Index so anyone can run `pip install zeroextract`:
```bash
pip install build twine
python -m build
twine upload dist/*
```

---

## 📄 License

MIT License. Free for personal and commercial use.
