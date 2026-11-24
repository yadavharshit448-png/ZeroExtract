"""Desktop Graphical User Interface for ZeroExtract."""

from __future__ import annotations

import os
from pathlib import Path
import queue
import sys
import threading
import time
from typing import Optional

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False

from zeroextract import __version__
from zeroextract.cli.ui import TerminalUI
from zeroextract.cli.windows_setup import normalize_windows_path
from zeroextract.fs.headroom import HeadroomMonitor


def launch_gui(initial_archive: str | None = None) -> int:
    """Launches the ZeroExtract Desktop Graphical User Interface."""
    if not HAS_TKINTER:
        print("[ERROR] Tkinter is not available in this Python environment.", file=sys.stderr)
        return 1

    root = tk.Tk()
    root.title(f"ZeroExtract v{__version__} - Zero-Extra-Space Extractor")
    root.geometry("680x560")
    root.minsize(580, 480)

    # Set icon if available
    icon_path = Path(__file__).resolve().parent.parent.parent / "zeroextract.ico"
    if icon_path.exists():
        try:
            root.iconbitmap(str(icon_path))
        except Exception:
            pass

    # Style configuration
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # Variables
    archive_var = tk.StringVar(value=normalize_windows_path(initial_archive or ""))
    output_dir_var = tk.StringVar()
    preverify_var = tk.BooleanVar(value=True)
    dry_run_var = tk.BooleanVar(value=False)
    status_var = tk.StringVar(value="Select an archive file to begin.")
    speed_eta_var = tk.StringVar(value="")
    free_space_var = tk.StringVar(value="")

    log_queue: queue.Queue[tuple[str, str]] = queue.Queue()
    is_extracting = False

    def update_free_space() -> None:
        target = output_dir_var.get().strip() or archive_var.get().strip()
        if target:
            try:
                mon = HeadroomMonitor()
                p = Path(target)
                check_p = p if p.is_dir() else p.parent
                if check_p.exists():
                    free_bytes = mon.get_free_space(check_p)
                    ui = TerminalUI()
                    free_space_var.set(f"Available Free Headroom: {ui.format_throughput(free_bytes).replace('/s', '')}")
            except Exception:
                free_space_var.set("")

    def browse_archive() -> None:
        if is_extracting:
            return
        filename = filedialog.askopenfilename(
            title="Select Game Archive",
            filetypes=[
                ("Game Archives (*.zip, *.rar, *.7z, *.001, *.z01)", "*.zip;*.zip64;*.z01;*.rar;*.7z;*.001"),
                ("ZIP Archives (*.zip)", "*.zip;*.zip64"),
                ("Multi-Part Slices (*.z01, *.part1.rar, *.001)", "*.z01;*.part1.rar;*.zip.001;*.001"),
                ("All Files (*.*)", "*.*"),
            ],
        )
        if filename:
            archive_var.set(filename)
            if not output_dir_var.get():
                p = Path(filename)
                output_dir_var.set(str(p.parent / p.stem))
            update_free_space()

    def browse_output() -> None:
        if is_extracting:
            return
        folder = filedialog.askdirectory(title="Select Destination Folder")
        if folder:
            output_dir_var.set(folder)
            update_free_space()

    # Main UI Layout
    main_frame = ttk.Frame(root, padding=16)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Header
    title_label = ttk.Label(
        main_frame,
        text="🚀 ZeroExtract",
        font=("Segoe UI", 16, "bold"),
    )
    title_label.pack(anchor="w")

    subtitle_label = ttk.Label(
        main_frame,
        text="Extract 50GB+ games without requiring double disk space. Space is recycled in-place.",
        font=("Segoe UI", 9),
    )
    subtitle_label.pack(anchor="w", pady=(2, 12))

    # Input Files section
    file_frame = ttk.LabelFrame(main_frame, text=" Archive & Destination ", padding=12)
    file_frame.pack(fill=tk.X, pady=(0, 10))

    # Archive Row
    ttk.Label(file_frame, text="Source Archive:").grid(row=0, column=0, sticky="w", pady=4)
    archive_entry = ttk.Entry(file_frame, textvariable=archive_var, width=50)
    archive_entry.grid(row=0, column=1, sticky="ew", padx=6, pady=4)
    browse_arch_btn = ttk.Button(file_frame, text="Browse...", command=browse_archive)
    browse_arch_btn.grid(row=0, column=2, padx=2, pady=4)

    # Destination Row
    ttk.Label(file_frame, text="Extract Destination:").grid(row=1, column=0, sticky="w", pady=4)
    out_entry = ttk.Entry(file_frame, textvariable=output_dir_var, width=50)
    out_entry.grid(row=1, column=1, sticky="ew", padx=6, pady=4)
    browse_out_btn = ttk.Button(file_frame, text="Browse...", command=browse_output)
    browse_out_btn.grid(row=1, column=2, padx=2, pady=4)

    file_frame.columnconfigure(1, weight=1)

    # Free Space Indicator
    headroom_lbl = ttk.Label(main_frame, textvariable=free_space_var, font=("Segoe UI", 8, "italic"), foreground="#007acc")
    headroom_lbl.pack(anchor="w", pady=(0, 6))

    # Options Frame
    opts_frame = ttk.Frame(main_frame)
    opts_frame.pack(fill=tk.X, pady=(0, 10))

    chk_verify = ttk.Checkbutton(
        opts_frame,
        text="0-Byte Preflight Verification (checks CRCs before extraction)",
        variable=preverify_var,
    )
    chk_verify.pack(side=tk.LEFT, padx=(0, 16))

    chk_dry = ttk.Checkbutton(
        opts_frame,
        text="Dry Run Simulation (test without writing)",
        variable=dry_run_var,
    )
    chk_dry.pack(side=tk.LEFT)

    # Progress Section
    prog_frame = ttk.LabelFrame(main_frame, text=" Extraction Progress ", padding=12)
    prog_frame.pack(fill=tk.X, pady=(0, 10))

    status_lbl = ttk.Label(prog_frame, textvariable=status_var, font=("Segoe UI", 9))
    status_lbl.pack(anchor="w", pady=(0, 4))

    progress_bar = ttk.Progressbar(prog_frame, mode="determinate")
    progress_bar.pack(fill=tk.X, pady=(0, 4))

    speed_lbl = ttk.Label(prog_frame, textvariable=speed_eta_var, font=("Segoe UI", 8))
    speed_lbl.pack(anchor="e")

    # Start Action Button
    action_btn = ttk.Button(
        main_frame,
        text="🚀 Extract Archive (Saves Disk Space)",
        style="Accent.TButton",
    )
    action_btn.pack(fill=tk.X, ipady=6, pady=(0, 10))

    # Activity Log
    log_frame = ttk.LabelFrame(main_frame, text=" Activity Log ", padding=8)
    log_frame.pack(fill=tk.BOTH, expand=True)

    log_text = tk.Text(log_frame, height=8, font=("Consolas", 8), wrap="word")
    log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
    log_text.configure(yscrollcommand=log_scroll.set)
    log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def append_log(message: str, level: str = "INFO") -> None:
        log_text.insert(tk.END, f"[{level}] {message}\n")
        log_text.see(tk.END)

    def check_log_queue() -> None:
        while not log_queue.empty():
            try:
                lvl, msg = log_queue.get_nowait()
                append_log(msg, lvl)
            except queue.Empty:
                break
        root.after(100, check_log_queue)

    # Extraction Worker Thread
    def extraction_worker() -> None:
        nonlocal is_extracting
        arch_p = archive_var.get().strip()
        out_p = output_dir_var.get().strip()
        is_dry = dry_run_var.get()
        no_ver = not preverify_var.get()

        from zeroextract.cli.main import extract_single_archive

        class GuiUI(TerminalUI):
            def render_info(self, msg: str) -> None:
                log_queue.put(("INFO", msg))
                root.after(0, lambda m=msg: status_var.set(m))

            def render_error(self, msg: str) -> None:
                log_queue.put(("ERROR", msg))
                root.after(0, lambda m=msg: status_var.set(f"Error: {m}"))

            def render_progress(
                self,
                current_bytes: int,
                total_bytes: int,
                current_member: str = "",
                speed: float = 0.0,
                eta: float = 0.0,
                force: bool = False,
            ) -> None:
                pct = (current_bytes / total_bytes * 100.0) if total_bytes > 0 else 100.0
                spd_str = self.format_throughput(speed)
                eta_str = self.format_eta(eta)
                root.after(0, lambda p=pct: progress_bar.configure(value=p))
                root.after(0, lambda s=spd_str, e=eta_str: speed_eta_var.set(f"{s} | ETA: {e}"))

        gui_ui = GuiUI(quiet=False)
        try:
            exit_code = extract_single_archive(
                archive_path_str=arch_p,
                output_dir_str=out_p,
                dry_run=is_dry,
                no_verify=no_ver,
                chunk_size=1048576,
                min_headroom=10 * 1024 * 1024,
                ui=gui_ui,
            )

            if exit_code == 0:
                root.after(0, lambda: progress_bar.configure(value=100))
                root.after(0, lambda: status_var.set("Extraction completed successfully!"))
                root.after(0, lambda: messagebox.showinfo(
                    "Extraction Complete",
                    "Game archive extracted successfully!\n\nPhysical disk space was recycled in-place."
                ))
            else:
                root.after(0, lambda: status_var.set("Extraction halted with errors."))
                root.after(0, lambda: messagebox.showerror(
                    "Extraction Error",
                    "Archive extraction failed. Please review the activity log for details."
                ))
        except Exception as exc:
            log_queue.put(("ERROR", str(exc)))
            root.after(0, lambda: messagebox.showerror("Fatal Error", f"Unhandled exception: {exc}"))
        finally:
            is_extracting = False
            root.after(0, lambda: action_btn.configure(state=tk.NORMAL))
            root.after(0, lambda: browse_arch_btn.configure(state=tk.NORMAL))
            root.after(0, lambda: browse_out_btn.configure(state=tk.NORMAL))

    def on_start_clicked() -> None:
        nonlocal is_extracting
        if is_extracting:
            return

        arch_p = archive_var.get().strip()
        if not arch_p:
            messagebox.showwarning("Archive Required", "Please select a game archive to extract.")
            return

        if not Path(arch_p).exists():
            messagebox.showerror("File Not Found", f"Archive file does not exist:\n{arch_p}")
            return

        if not output_dir_var.get().strip():
            p = Path(arch_p)
            output_dir_var.set(str(p.parent / p.stem))

        is_extracting = True
        action_btn.configure(state=tk.DISABLED)
        browse_arch_btn.configure(state=tk.DISABLED)
        browse_out_btn.configure(state=tk.DISABLED)
        progress_bar.configure(value=0)
        status_var.set("Initializing extraction pipeline...")

        t = threading.Thread(target=extraction_worker, daemon=True)
        t.start()

    action_btn.configure(command=on_start_clicked)

    # Initial updates
    update_free_space()
    check_log_queue()

    root.mainloop()
    return 0


__all__ = ["launch_gui"]
