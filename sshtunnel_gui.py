import json
import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    import paramiko
    if not hasattr(paramiko, "DSSKey"):
        class UnsupportedDSSKey:
            @classmethod
            def from_private_key_file(cls, *_args, **_kwargs):
                raise paramiko.SSHException("DSA/DSS keys are not supported by this Paramiko version.")

        paramiko.DSSKey = UnsupportedDSSKey
    from sshtunnel import SSHTunnelForwarder
except ImportError:  # pragma: no cover - handled in UI at runtime
    paramiko = None
    SSHTunnelForwarder = None


APP_TITLE = "SSH Tunnel Helper"
PROFILE_PATH = Path.home() / ".ssh_tunnel_helper_profiles.json"
APP_DIR = Path(__file__).resolve().parent
ICON_PNG_PATH = APP_DIR / "assets" / "app_icon.png"
ICON_ICO_PATH = APP_DIR / "assets" / "app_icon.ico"


class QueueLogHandler(logging.Handler):
    def __init__(self, events):
        super().__init__()
        self.events = events
        self.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    def emit(self, record):
        self.events.put(("log", self.format(record)))


class TunnelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x700")
        self.minsize(900, 640)
        self.icon_image = None
        self.set_window_icon()

        self.server = None
        self.worker = None
        self.events = queue.Queue()
        self.tunnel_logger = self.build_tunnel_logger()
        self.profiles = self.load_profiles()

        self.vars = {
            "profile": tk.StringVar(),
            "ssh_host": tk.StringVar(),
            "ssh_port": tk.StringVar(value="22"),
            "ssh_user": tk.StringVar(),
            "auth_mode": tk.StringVar(value="password"),
            "ssh_password": tk.StringVar(),
            "ssh_key": tk.StringVar(),
            "remote_host": tk.StringVar(value="127.0.0.1"),
            "remote_port": tk.StringVar(),
            "local_host": tk.StringVar(value="127.0.0.1"),
            "local_port": tk.StringVar(),
        }
        for key in ("remote_host", "remote_port", "local_host", "local_port"):
            self.vars[key].trace_add("write", lambda *_args: self.draw_diagram())

        self.configure_style()
        self.build_ui()
        self.refresh_profile_list()
        self.after(120, self.process_events)

    def set_window_icon(self):
        try:
            if ICON_ICO_PATH.exists():
                self.iconbitmap(str(ICON_ICO_PATH))
            if ICON_PNG_PATH.exists():
                self.icon_image = tk.PhotoImage(file=str(ICON_PNG_PATH))
                self.iconphoto(True, self.icon_image)
        except tk.TclError:
            pass

    def build_tunnel_logger(self):
        logger = logging.getLogger(f"{APP_TITLE}.{id(self)}")
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(QueueLogHandler(self.events))
        return logger

    def configure_style(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Good.TLabel", foreground="#167a37")
        style.configure("Warn.TLabel", foreground="#9a6700")
        style.configure("Danger.TLabel", foreground="#b42318")
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))

    def build_ui(self):
        root = ttk.Frame(self, padding=16)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=0)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(1, weight=1)

        header = ttk.Frame(root)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.columnconfigure(1, weight=1)

        title = ttk.Label(header, text=APP_TITLE, style="Title.TLabel")
        title.grid(row=0, column=0, sticky="w")

        subtitle = ttk.Label(
            header,
            text="Create a secure local port that forwards through an SSH server to a remote service.",
        )
        subtitle.grid(row=0, column=1, sticky="e", padx=(20, 0))

        left = ttk.Frame(root)
        left.grid(row=1, column=0, sticky="ns", pady=(14, 0), padx=(0, 16))
        right = ttk.Frame(root)
        right.grid(row=1, column=1, sticky="nsew", pady=(14, 0))
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self.build_form(left)
        self.build_visual(right)
        self.build_log(right)

    def build_form(self, parent):
        form = ttk.LabelFrame(parent, text="Tunnel settings", padding=12)
        form.pack(fill="y")

        self.add_profile_controls(form)
        self.add_separator(form, 2)

        row = 3
        row = self.add_entry(form, row, "SSH server", "ssh_host", "Example: bastion.example.com")
        row = self.add_entry(form, row, "SSH port", "ssh_port", "Usually 22")
        row = self.add_entry(form, row, "SSH username", "ssh_user", "Your SSH login name")

        ttk.Label(form, text="Authentication").grid(row=row, column=0, sticky="w", pady=6)
        auth = ttk.Frame(form)
        auth.grid(row=row, column=1, sticky="ew", pady=6)
        ttk.Radiobutton(auth, text="Password", variable=self.vars["auth_mode"], value="password", command=self.update_auth_state).pack(side="left")
        ttk.Radiobutton(auth, text="Private key", variable=self.vars["auth_mode"], value="key", command=self.update_auth_state).pack(side="left", padx=(12, 0))
        row += 1

        self.password_entry, row = self.add_tracked_entry(
            form,
            row,
            "SSH password",
            "ssh_password",
            "Stored only in memory",
            show="*",
        )

        ttk.Label(form, text="Private key").grid(row=row, column=0, sticky="w", pady=6)
        key_frame = ttk.Frame(form)
        key_frame.grid(row=row, column=1, sticky="ew", pady=6)
        key_frame.columnconfigure(0, weight=1)
        self.key_entry = ttk.Entry(key_frame, textvariable=self.vars["ssh_key"], width=34)
        self.key_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(key_frame, text="Browse", command=self.pick_key).grid(row=0, column=1, padx=(6, 0))
        row += 1

        self.add_separator(form, row)
        row += 1

        row = self.add_entry(form, row, "Remote host", "remote_host", "Seen from SSH server")
        row = self.add_entry(form, row, "Remote port", "remote_port", "5432, 3306, 8080...")
        row = self.add_entry(form, row, "Local bind host", "local_host", "127.0.0.1 is safest")
        row = self.add_entry(form, row, "Local port", "local_port", "Port on this computer")

        self.add_separator(form, row)
        row += 1

        actions = ttk.Frame(form)
        actions.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        actions.columnconfigure((0, 1), weight=1)
        self.start_button = ttk.Button(actions, text="Start tunnel", style="Primary.TButton", command=self.start_tunnel)
        self.start_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.stop_button = ttk.Button(actions, text="Stop tunnel", command=self.stop_tunnel, state="disabled")
        self.stop_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        row += 1

        self.status_label = ttk.Label(form, text="Status: not connected", style="Warn.TLabel")
        self.status_label.grid(row=row, column=0, columnspan=2, sticky="w", pady=(12, 0))

        for child in form.winfo_children():
            child.grid_configure(padx=2)
        form.columnconfigure(1, weight=1)
        self.update_auth_state()

    def add_profile_controls(self, form):
        ttk.Label(form, text="Profile").grid(row=0, column=0, sticky="w", pady=6)
        combo = ttk.Combobox(form, textvariable=self.vars["profile"], state="readonly", width=32)
        combo.grid(row=0, column=1, sticky="ew", pady=6)
        combo.bind("<<ComboboxSelected>>", lambda _event: self.load_selected_profile())
        self.profile_combo = combo

        buttons = ttk.Frame(form)
        buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        buttons.columnconfigure((0, 1, 2), weight=1)
        ttk.Button(buttons, text="Save profile", command=self.save_profile).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(buttons, text="Delete", command=self.delete_profile).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(buttons, text="Clear", command=self.clear_form).grid(row=0, column=2, sticky="ew", padx=(4, 0))

    def add_entry(self, form, row, label, key, help_text, show=None):
        del help_text
        ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=(6, 0))
        entry = ttk.Entry(form, textvariable=self.vars[key], width=32, show=show)
        entry.grid(row=row, column=1, sticky="ew", pady=(6, 0))
        return row + 1

    def add_tracked_entry(self, form, row, label, key, help_text, show=None):
        del help_text
        ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=(6, 0))
        entry = ttk.Entry(form, textvariable=self.vars[key], width=32, show=show)
        entry.grid(row=row, column=1, sticky="ew", pady=(6, 0))
        return entry, row + 1

    def add_separator(self, form, row):
        ttk.Separator(form).grid(row=row, column=0, columnspan=2, sticky="ew", pady=10)

    def build_visual(self, parent):
        panel = ttk.LabelFrame(parent, text="What this tunnel does", padding=12)
        panel.grid(row=0, column=0, sticky="ew")
        panel.columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(panel, width=470, height=220, background="#f7f9fc", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="ew")
        self.canvas.bind("<Configure>", lambda _event: self.draw_diagram())

        explanation = ttk.Label(
            panel,
            text=(
                "Use your app with the local address. Traffic is encrypted to the SSH server, "
                "then forwarded to the remote host and port."
            ),
            wraplength=470,
        )
        explanation.grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.draw_diagram()

    def build_log(self, parent):
        panel = ttk.LabelFrame(parent, text="Connection log", padding=12)
        panel.grid(row=1, column=0, sticky="nsew", pady=(14, 0))
        panel.rowconfigure(0, weight=1)
        panel.columnconfigure(0, weight=1)

        self.log = tk.Text(panel, width=54, height=12, wrap="word", state="disabled")
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(panel, command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

    def draw_diagram(self):
        canvas = self.canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 1)
        left_margin = 24
        right_margin = 24
        usable_width = max(width - left_margin - right_margin, 260)
        box_width = min(150, max(82, (usable_width - 16) / 3))
        gap = max(8, (usable_width - (3 * box_width)) / 2)
        first_x = left_margin
        middle_x = first_x + box_width + gap
        third_x = middle_x + box_width + gap
        y = 90
        boxes = [
            (first_x, "Your computer", "localhost"),
            (middle_x, "SSH server", "encrypted hop"),
            (third_x, "Remote service", "database / web / API"),
        ]

        for x, title, note in boxes:
            canvas.create_rectangle(x, y - 42, x + box_width, y + 42, fill="white", outline="#9fb3c8", width=2)
            canvas.create_text(x + box_width / 2, y - 10, text=title, font=("Segoe UI", 10, "bold"), fill="#17324d")
            canvas.create_text(x + box_width / 2, y + 16, text=note, font=("Segoe UI", 8), fill="#5f6b7a")

        self.arrow(first_x + box_width, y, middle_x, y, "#1f6feb", "SSH tunnel")
        self.arrow(middle_x + box_width, y, third_x, y, "#6f42c1", "forward")

        local = f'{self.vars["local_host"].get() or "127.0.0.1"}:{self.vars["local_port"].get() or "local port"}'
        remote = f'{self.vars["remote_host"].get() or "remote host"}:{self.vars["remote_port"].get() or "remote port"}'
        canvas.create_text(left_margin, 166, text=f"Connect your app to {local}", anchor="w", fill="#17324d", font=("Segoe UI", 9, "bold"))
        canvas.create_text(left_margin, 190, text=f"SSH server reaches {remote}", anchor="w", fill="#17324d", font=("Segoe UI", 9, "bold"))

    def arrow(self, x1, y1, x2, y2, color, label):
        if x2 <= x1 + 8:
            return
        self.canvas.create_line(x1 + 6, y1, x2 - 6, y2, arrow="last", width=3, fill=color, smooth=True)
        self.canvas.create_text((x1 + x2) / 2, y1 - 24, text=label, fill=color, font=("Segoe UI", 10, "bold"))

    def update_auth_state(self):
        password = self.vars["auth_mode"].get() == "password"
        self.password_entry.configure(state="normal" if password else "disabled")
        self.key_entry.configure(state="disabled" if password else "normal")

    def pick_key(self):
        path = filedialog.askopenfilename(title="Choose SSH private key")
        if path:
            self.vars["ssh_key"].set(path)

    def start_tunnel(self):
        if SSHTunnelForwarder is None:
            messagebox.showerror("Missing dependency", "Install dependencies first:\n\npython -m pip install -r requirements.txt")
            return

        if paramiko is None:
            messagebox.showerror(
                "Incompatible dependency",
                "Paramiko is missing.\n\n"
                f"Fix it with:\n\npython -m pip install -U -r \"{Path(__file__).with_name('requirements.txt')}\"",
            )
            return

        try:
            config = self.read_config()
        except ValueError as exc:
            messagebox.showwarning("Check settings", str(exc))
            return

        self.set_running(True)
        self.write_log("Starting tunnel...")
        self.worker = threading.Thread(target=self.run_tunnel, args=(config,), daemon=True)
        self.worker.start()

    def read_config(self):
        required = ["ssh_host", "ssh_user", "remote_host", "remote_port", "local_host", "local_port"]
        missing = [key for key in required if not self.vars[key].get().strip()]
        if missing:
            labels = ", ".join(key.replace("_", " ") for key in missing)
            raise ValueError(f"Fill in required fields: {labels}.")

        try:
            ssh_port = int(self.vars["ssh_port"].get())
            remote_port = int(self.vars["remote_port"].get())
            local_port = int(self.vars["local_port"].get())
        except ValueError as exc:
            raise ValueError("SSH port, remote port, and local port must be numbers.") from exc

        config = {
            "ssh_address_or_host": (self.vars["ssh_host"].get().strip(), ssh_port),
            "ssh_username": self.vars["ssh_user"].get().strip(),
            "remote_bind_address": (self.vars["remote_host"].get().strip(), remote_port),
            "local_bind_address": (self.vars["local_host"].get().strip(), local_port),
        }

        if self.vars["auth_mode"].get() == "password":
            if not self.vars["ssh_password"].get():
                raise ValueError("Enter the SSH password or switch to private key authentication.")
            config["ssh_password"] = self.vars["ssh_password"].get()
        else:
            key_path = self.vars["ssh_key"].get().strip()
            if not key_path:
                raise ValueError("Choose a private key file or switch to password authentication.")
            config["ssh_pkey"] = key_path

        return config

    def build_ssh_client(self, config):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_options = {
            "hostname": config["ssh_address_or_host"][0],
            "port": config["ssh_address_or_host"][1],
            "username": config["ssh_username"],
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
        }
        if "ssh_password" in config:
            connect_options["password"] = config["ssh_password"]
        else:
            connect_options["key_filename"] = config["ssh_pkey"]
        client.connect(**connect_options)
        return client

    def test_remote_target(self, config):
        remote_host, remote_port = config["remote_bind_address"]
        client = self.build_ssh_client(config)
        try:
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("SSH authentication succeeded, but the SSH transport is not active.")
            channel = transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                ("127.0.0.1", 0),
                timeout=10,
            )
            channel.close()
        finally:
            client.close()

    def run_tunnel(self, config):
        try:
            remote_host, remote_port = config["remote_bind_address"]
            self.events.put(("log", f"Checking remote target from SSH server: {remote_host}:{remote_port}"))
            self.test_remote_target(config)
            self.events.put(("log", "Remote target check passed. Starting local listener..."))
            self.server = SSHTunnelForwarder(**config, logger=self.tunnel_logger)
            self.server.start()
            local_host, local_port = self.server.local_bind_address
            self.events.put((
                "connected",
                f"Tunnel active at {local_host}:{local_port}. Connect your app to this local address.",
            ))
        except Exception as exc:
            remote_host, remote_port = config["remote_bind_address"]
            local_host, local_port = config["local_bind_address"]
            self.events.put((
                "failed",
                "Could not open the remote side of the tunnel.\n\n"
                f"Testing {local_host}:{local_port} only proves the local listener is open. "
                f"The SSH server must also be able to reach {remote_host}:{remote_port}.\n\n"
                f"Details: {exc}",
            ))

    def stop_tunnel(self):
        if self.server:
            self.write_log("Stopping tunnel...")
            try:
                self.server.stop()
            except Exception as exc:
                self.write_log(f"Stop warning: {exc}")
            self.server = None
        self.set_running(False)
        self.write_log("Tunnel stopped.")

    def process_events(self):
        while not self.events.empty():
            kind, message = self.events.get()
            self.write_log(message)
            if kind == "connected":
                self.status_label.configure(text=f"Status: connected - {message}", style="Good.TLabel")
                self.start_button.configure(state="disabled")
                self.stop_button.configure(state="normal")
            elif kind == "log":
                continue
            elif kind == "failed":
                self.set_running(False)
                messagebox.showerror("Tunnel failed", message)
        self.draw_diagram()
        self.after(120, self.process_events)

    def set_running(self, running):
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        if running:
            self.status_label.configure(text="Status: connecting...", style="Warn.TLabel")
        else:
            self.status_label.configure(text="Status: not connected", style="Warn.TLabel")

    def write_log(self, message):
        self.log.configure(state="normal")
        self.log.insert("end", f"{message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def load_profiles(self):
        if not PROFILE_PATH.exists():
            return {}
        try:
            return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def persist_profiles(self):
        PROFILE_PATH.write_text(json.dumps(self.profiles, indent=2), encoding="utf-8")

    def refresh_profile_list(self):
        names = sorted(self.profiles)
        self.profile_combo.configure(values=names)
        if self.vars["profile"].get() not in names:
            self.vars["profile"].set(names[0] if names else "")

    def profile_data(self):
        keys = [key for key in self.vars if key not in {"profile", "ssh_password"}]
        return {key: self.vars[key].get() for key in keys}

    def save_profile(self):
        name = self.vars["profile"].get().strip()
        if not name:
            name = simpledialog.askstring("Profile name", "Name this tunnel profile:", parent=self)
            if not name:
                return
            name = name.strip()
            if not name:
                return
            self.vars["profile"].set(name)
        self.profiles[name] = self.profile_data()
        self.persist_profiles()
        self.refresh_profile_list()
        self.write_log(f'Profile "{name}" saved. Passwords are not saved.')

    def load_selected_profile(self):
        data = self.profiles.get(self.vars["profile"].get())
        if not data:
            return
        for key, value in data.items():
            if key in self.vars:
                self.vars[key].set(value)
        self.update_auth_state()
        self.draw_diagram()
        self.write_log(f'Profile "{self.vars["profile"].get()}" loaded.')

    def delete_profile(self):
        name = self.vars["profile"].get()
        if not name or name not in self.profiles:
            return
        if messagebox.askyesno("Delete profile", f'Delete profile "{name}"?'):
            del self.profiles[name]
            self.persist_profiles()
            self.refresh_profile_list()
            self.write_log(f'Profile "{name}" deleted.')

    def clear_form(self):
        for key, var in self.vars.items():
            var.set("")
        self.vars["ssh_port"].set("22")
        self.vars["auth_mode"].set("password")
        self.vars["remote_host"].set("127.0.0.1")
        self.vars["local_host"].set("127.0.0.1")
        self.update_auth_state()
        self.draw_diagram()

    def destroy(self):
        if self.server:
            self.stop_tunnel()
        super().destroy()


if __name__ == "__main__":
    app = TunnelApp()
    app.mainloop()
