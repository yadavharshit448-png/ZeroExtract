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
    from tkinter import filedialog, messagebox, simpledialog, ttk
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore
    HAS_TKDND = True
except ImportError:
    HAS_TKDND = False

from zeroextract import __version__
from zeroextract.cli.ui import TerminalUI
from zeroextract.cli.windows_setup import normalize_windows_path
from zeroextract.fs.headroom import HeadroomMonitor


def _format_bytes_human(num_bytes: int) -> str:
    """Formats a byte count into a human-readable string."""
    size = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{int(num_bytes)} B"


def _parse_drop_paths(raw_data: str) -> list[str]:
    """Parses TkDND drop payload (handles braced paths with spaces)."""
    paths: list[str] = []
    buf = ""
    in_braces = False
    for ch in raw_data:
        if ch == "{":
            in_braces = True
            buf = ""
        elif ch == "}":
            in_braces = False
            if buf:
                paths.append(buf)
                buf = ""
        elif ch == " " and not in_braces:
            if buf:
                paths.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        paths.append(buf)
    return paths


def launch_gui(initial_archive: str | None = None) -> int:
    """Launches the ZeroExtract Desktop Graphical User Interface."""
    if not HAS_TKINTER:
        print("[ERROR] Tkinter is not available in this Python environment.", file=sys.stderr)
        return 1

    root = TkinterDnD.Tk() if HAS_TKDND else tk.Tk()
    root.title(f"ZeroExtract v{__version__} - Zero-Extra-Space Extractor")
    root.geometry("700x620")
    root.minsize(600, 520)

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
    password_var = tk.StringVar()
    show_password_var = tk.BooleanVar(value=False)
    preverify_var = tk.BooleanVar(value=True)
    dry_run_var = tk.BooleanVar(value=False)
    status_var = tk.StringVar(value="Select or drop an archive file to begin.")
    speed_eta_var = tk.StringVar(value="")
    free_space_var = tk.StringVar(value="")
    peak_saved_var = tk.StringVar(value="Peak Space Saved: 0 B")

    log_queue: queue.Queue[tuple[str, str]] = queue.Queue()
    is_extracting = False
    cancel_event = threading.Event()
    peak_saved_bytes = 0
    saved_lock = threading.Lock()

    def load_archive_path(raw_path: str) -> None:
        if is_extracting:
            return
        cleaned = normalize_windows_path(raw_path)
        if not cleaned:
            return
        archive_var.set(cleaned)
        p = Path(cleaned)
        if not output_dir_var.get().strip():
            output_dir_var.set(str(p.parent / p.stem))
        update_free_space()

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
            load_archive_path(filename)

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

    # Password Row (optional)
    ttk.Label(file_frame, text="Password (optional):").grid(row=2, column=0, sticky="w", pady=4)
    pwd_entry = ttk.Entry(file_frame, textvariable=password_var, show="*", width=50)
    pwd_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=4)

    def toggle_password() -> None:
        pwd_entry.configure(show="" if show_password_var.get() else "*")

    show_pwd_chk = ttk.Checkbutton(file_frame, text="Show", variable=show_password_var, command=toggle_password)
    show_pwd_chk.grid(row=2, column=2, padx=2, pady=4, sticky="w")

    file_frame.columnconfigure(1, weight=1)

    if HAS_TKDND:
        try:
            root.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
            root.dnd_bind(  # type: ignore[attr-defined]
                "<<Drop>>",
                lambda e: load_archive_path(_parse_drop_paths(e.data)[0]) if _parse_drop_paths(e.data) else None,
            )
        except Exception:
            pass

    # Free Space & Peak Space Saved Indicators
    metrics_frame = ttk.Frame(main_frame)
    metrics_frame.pack(fill=tk.X, pady=(0, 6))
    headroom_lbl = ttk.Label(metrics_frame, textvariable=free_space_var, font=("Segoe UI", 8, "italic"), foreground="#007acc")
    headroom_lbl.pack(side=tk.LEFT)
    peak_saved_lbl = ttk.Label(metrics_frame, textvariable=peak_saved_var, font=("Segoe UI", 8, "bold"), foreground="#2e7d32")
    peak_saved_lbl.pack(side=tk.RIGHT)

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

    # Action Buttons (Extract + Safe Cancel/Pause)
    btn_frame = ttk.Frame(main_frame)
    btn_frame.pack(fill=tk.X, pady=(0, 10))

    action_btn = ttk.Button(
        btn_frame,
        text="Extract Archive (Saves Disk Space)",
        style="Accent.TButton",
    )
    action_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6, padx=(0, 6))

    cancel_btn = ttk.Button(
        btn_frame,
        text="Pause / Cancel",
        state=tk.DISABLED,
    )
    cancel_btn.pack(side=tk.RIGHT, ipady=6)

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
        nonlocal is_extracting, peak_saved_bytes
        arch_p = archive_var.get().strip()
        out_p = output_dir_var.get().strip()
        pwd_val = password_var.get() or None
        is_dry = dry_run_var.get()
        no_ver = not preverify_var.get()

        from zeroextract.cli.main import extract_single_archive

        def record_space_saved(delta: int) -> None:
            nonlocal peak_saved_bytes
            if delta <= 0:
                return
            with saved_lock:
                peak_saved_bytes += delta
                total_saved = peak_saved_bytes
            root.after(0, lambda s=total_saved: peak_saved_var.set(f"Peak Space Saved: {_format_bytes_human(s)}"))

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
                password=pwd_val,
                cancel_event=cancel_event,
                on_space_saved=record_space_saved,
            )

            if exit_code == 0:
                root.after(0, lambda: progress_bar.configure(value=100))
                root.after(0, lambda: status_var.set("Extraction completed successfully!"))
                root.after(0, lambda: messagebox.showinfo(
                    "Extraction Complete",
                    "Game archive extracted successfully!\n\nPhysical disk space was recycled in-place."
                ))
            elif exit_code == 130:
                root.after(0, lambda: status_var.set("Paused safely. Click Extract to resume from .unpack_journal.json."))
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
            cancel_event.clear()
            root.after(0, lambda: action_btn.configure(state=tk.NORMAL))
            root.after(0, lambda: cancel_btn.configure(state=tk.DISABLED))
            root.after(0, lambda: browse_arch_btn.configure(state=tk.NORMAL))
            root.after(0, lambda: browse_out_btn.configure(state=tk.NORMAL))

    def on_cancel_clicked() -> None:
        if not is_extracting:
            return
        cancel_event.set()
        cancel_btn.configure(state=tk.DISABLED)
        status_var.set("Pausing extraction safely (saving journal for resume)...")

    def on_start_clicked() -> None:
        nonlocal is_extracting, peak_saved_bytes
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

        # Prompt for password if archive is encrypted and password field is empty
        if not password_var.get() and preverify_var.get():
            from zeroextract.safety.preverify import PreflightShield
            ok, errs = PreflightShield().verify_archive(arch_p)
            if not ok and any("password" in e.lower() or "encrypted" in e.lower() for e in errs):
                entered = simpledialog.askstring(
                    "Archive Password Required",
                    f"'{Path(arch_p).name}' is password-protected.\nEnter archive password:",
                    show="*",
                    parent=root,
                )
                if entered is None:
                    return
                password_var.set(entered)

        cancel_event.clear()
        peak_saved_bytes = 0
        peak_saved_var.set("Peak Space Saved: 0 B")
        is_extracting = True
        action_btn.configure(state=tk.DISABLED)
        cancel_btn.configure(state=tk.NORMAL)
        browse_arch_btn.configure(state=tk.DISABLED)
        browse_out_btn.configure(state=tk.DISABLED)
        progress_bar.configure(value=0)
        status_var.set("Initializing extraction pipeline...")

        t = threading.Thread(target=extraction_worker, daemon=True)
        t.start()

    action_btn.configure(command=on_start_clicked)
    cancel_btn.configure(command=on_cancel_clicked)

    # Initial updates
    update_free_space()
    check_log_queue()

    root.mainloop()
    return 0


__all__ = ["launch_gui"]
