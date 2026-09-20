#!/usr/bin/env python3
"""
CertHelm - installeur de l'agent de decouverte de certificats (Windows).

Un seul fichier a remettre a l'administrateur du serveur : CertHelmAgent_Setup.exe
embarque l'agent. Il demande l'adresse de CertHelm et le jeton, verifie qu'ils sont
valides, copie l'agent dans un dossier reserve aux administrateurs
(C:\\Program Files\\CertHelmAgent), l'enregistre pour demarrer avec Windows, puis
attend que le serveur apparaisse dans la console CertHelm avant de dire "termine".

Modes de lancement de l'agent :
  - tache en arriere-plan (serveurs) : tourne en continu sous SYSTEM, pilotable
    depuis CertHelm, redemarre seul en cas de plantage ;
  - icone barre des taches (postes de travail) ;
  - rien : ecrit seulement la configuration.

Deploiement sans interface (GPO, script) :
  CertHelmAgent_Setup.exe --silent --controller-url http://10.0.0.5:8765 --token XXXX [--allow-renewal]
  CertHelmAgent_Setup.exe --uninstall

Le coeur (classe Installer) n'utilise aucune interface : tkinter n'est charge que pour
la fenetre, ce qui permet de le tester automatiquement.
"""

import argparse
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
    BUNDLE_DIR = getattr(sys, "_MEIPASS", APP_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR

AGENT_EXE_NAME = "CertHelmAgent.exe"
TASK_NAME = "CertHelmAgent"
DEFAULT_INSTALL_DIR = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "CertHelmAgent")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # keep powershell/schtasks from flashing a console
REGISTRATION_WAIT_SECONDS = 90
MODES = ("schedule", "tray", "manual")

BG = "#121316"
CARD = "#1a1c20"
BORDER = "#2a2d33"
TEXT = "#d1d5db"
BRIGHT = "#ffffff"
MUTED = "#8b93a1"
ACCENT = "#009FDF"
OK = "#10b981"
WARN = "#f59e0b"
BAD = "#ef4444"


class InstallError(Exception):
    """A failure whose message is meant to be read by the administrator."""


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def normalize_url(url):
    url = (url or "").strip().rstrip("/")
    if not url:
        raise InstallError("L'adresse de CertHelm est requise (ex. http://10.0.0.5:8765).")
    if "://" not in url:
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InstallError("Adresse invalide : elle doit ressembler à http://10.0.0.5:8765")
    for suffix in ("/agent/checkin", "/agent/poll"):  # tolerate the full URL being pasted
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    return url


def verify_controller(url, token, hostname, timeout=6):
    """Checks that CertHelm answers AND accepts this token. Returns {'registered': bool|None,
    'token_checked': bool}. Raises InstallError with a message an administrator can act on."""
    url = normalize_url(url)
    token = (token or "").strip()
    if not token:
        raise InstallError("Le jeton est requis (CertHelm → Paramètres → Agents & Découverte).")
    req = urllib.request.Request(url + "/agent/verify", data=json.dumps({"hostname": hostname}).encode(),
                                 method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return {"registered": bool(body.get("registered")), "token_checked": True}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise InstallError("CertHelm répond mais refuse ce jeton (jeton incorrect, ou régénéré depuis).")
        if e.code == 404:
            # An older CertHelm without /agent/verify: at least make sure it is reachable.
            try:
                with urllib.request.urlopen(url + "/agent/ping", timeout=timeout):
                    return {"registered": None, "token_checked": False}
            except Exception:
                pass
            raise InstallError("Cette adresse répond, mais ce n'est pas CertHelm (port ou adresse incorrects ?).")
        raise InstallError(f"CertHelm a répondu une erreur inattendue (HTTP {e.code}).")
    except urllib.error.URLError as e:
        raise InstallError(f"Impossible de joindre CertHelm à {url} : {e.reason}. Vérifiez l'adresse, le port "
                           "et le pare-feu de la machine CertHelm.")
    except Exception as e:
        raise InstallError(f"Réponse illisible de {url} : {e}")


def _run(cmd, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True, creationflags=NO_WINDOW)
    if check and result.returncode != 0:
        raise InstallError((result.stderr or result.stdout or f"code {result.returncode}").strip()[:400])
    return result


def task_state():
    """'Running', 'Ready', 'Disabled'... or None when the background task is not installed."""
    result = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   f"(Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue).State"], check=False)
    state = (result.stdout or "").strip()
    return state or None


def find_agent_source():
    for folder in (BUNDLE_DIR, APP_DIR):
        path = os.path.join(folder, AGENT_EXE_NAME)
        if os.path.isfile(path):
            return path
    return None


def read_existing_config(install_dir=DEFAULT_INSTALL_DIR):
    try:
        with open(os.path.join(install_dir, "agent_config.json"), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def startup_script_path():
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs",
                        "Startup", "CertHelmAgentTray.bat")


class Installer:
    """Everything the installer does, with no user interface. `log` receives progress lines."""

    def __init__(self, log=print):
        self.log = log

    # ---- pieces ----

    def stop_running_agent(self):
        _run(["schtasks", "/end", "/tn", TASK_NAME], check=False)
        _run(["taskkill", "/F", "/IM", AGENT_EXE_NAME], check=False)
        time.sleep(1)  # let Windows release the file before it is overwritten

    def copy_agent(self, install_dir):
        source = find_agent_source()
        if not source:
            raise InstallError("CertHelmAgent.exe est introuvable : ce programme d'installation est incomplet. "
                               "Demandez-en une copie neuve.")
        os.makedirs(install_dir, exist_ok=True)
        dest = os.path.join(install_dir, AGENT_EXE_NAME)
        if os.path.abspath(source).lower() != os.path.abspath(dest).lower():
            shutil.copy2(source, dest)
        return dest

    def write_config(self, install_dir, url, token, hostname, allow_renewal):
        config = {"controller_url": url, "token": token, "hostname": hostname}
        if allow_renewal:
            config["allow_cert_management"] = True
        path = os.path.join(install_dir, "agent_config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return path

    def lock_folder(self, install_dir):
        """The agent runs as SYSTEM and its config holds the token: only SYSTEM and the
        Administrators group may touch this folder (well-known SIDs, so any Windows language works)."""
        result = _run(["icacls", install_dir, "/inheritance:r", "/grant", "*S-1-5-18:(OI)(CI)F",
                       "/grant", "*S-1-5-32-544:(OI)(CI)F"], check=False)
        if result.returncode != 0:
            self.log("Attention : les droits du dossier n'ont pas pu être restreints aux administrateurs.")

    def register_background_task(self, exe):
        workdir = os.path.dirname(exe)
        q = lambda text: text.replace("'", "''")
        script = (
            "$ErrorActionPreference='Stop';"
            f"$a=New-ScheduledTaskAction -Execute '{q(exe)}' -Argument '--daemon' -WorkingDirectory '{q(workdir)}';"
            "$t=New-ScheduledTaskTrigger -AtStartup;"
            "$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 "
            "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries "
            "-DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;"
            "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
            f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Settings $s -Principal $p "
            "-Description 'Agent de decouverte de certificats CertHelm' -Force | Out-Null"
        )
        _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        _run(["schtasks", "/run", "/tn", TASK_NAME])

    def register_tray(self, exe):
        # One agent per machine: the background task would duplicate the tray icon.
        _run(["schtasks", "/end", "/tn", TASK_NAME], check=False)
        _run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], check=False)
        os.makedirs(os.path.dirname(startup_script_path()), exist_ok=True)
        with open(startup_script_path(), "w", encoding="utf-8") as f:
            f.write(f'@echo off\nstart "" "{exe}" --tray\n')
        subprocess.Popen([exe, "--tray"], cwd=os.path.dirname(exe),
                         creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)

    def wait_until_registered(self, url, token, hostname, timeout=None, interval=3):
        deadline = time.monotonic() + (REGISTRATION_WAIT_SECONDS if timeout is None else timeout)
        while time.monotonic() < deadline:
            try:
                if verify_controller(url, token, hostname, timeout=5)["registered"]:
                    return True
            except InstallError:
                pass
            time.sleep(interval)
        return False

    # ---- whole operations ----

    def install(self, url, token, hostname, mode="schedule", allow_renewal=False, install_dir=DEFAULT_INSTALL_DIR,
                wait=True):
        """Returns a dict {ok, registered, message}. Raises InstallError on a hard failure."""
        if mode not in MODES:
            raise InstallError(f"Mode inconnu : {mode}")
        hostname = (hostname or "").strip() or socket.gethostname()
        url = normalize_url(url)
        if mode != "manual" and not is_admin():
            raise InstallError("Droits administrateur requis : relancez l'installeur avec « Exécuter en tant "
                               "qu'administrateur ».")

        self.log("Vérification de CertHelm et du jeton...")
        check = verify_controller(url, token, hostname)
        self.log("Connexion à CertHelm réussie." if check["token_checked"]
                 else "CertHelm joignable (version ancienne : jeton non vérifiable à l'avance).")

        self.log("Arrêt de l'agent précédent (s'il existe)...")
        self.stop_running_agent()
        self.log(f"Copie de l'agent dans {install_dir} ...")
        try:
            exe = self.copy_agent(install_dir)
            self.write_config(install_dir, url, token.strip(), hostname, allow_renewal)
        except PermissionError as e:
            raise InstallError(f"Accès refusé à {e.filename or install_dir}. Relancez l'installeur en tant "
                               "qu'administrateur, ou fermez l'agent s'il est déjà en cours d'exécution.")
        except OSError as e:
            raise InstallError(f"Impossible d'écrire dans {install_dir} : {e}")
        self.lock_folder(install_dir)

        if mode == "schedule":
            self.log("Enregistrement de la tâche Windows (démarrage automatique, compte SYSTEM)...")
            self.register_background_task(exe)
        elif mode == "tray":
            self.log("Lancement de l'icône de la barre des tâches...")
            self.register_tray(exe)
        else:
            return {"ok": True, "registered": None,
                    "message": f"Configuration enregistrée dans {install_dir}. Lancez CertHelmAgent.exe quand vous voulez."}

        if not wait:
            return {"ok": True, "registered": None, "message": "Agent installé et démarré."}
        self.log(f"Attente de l'apparition du serveur dans CertHelm (jusqu'à {REGISTRATION_WAIT_SECONDS} s)...")
        registered = self.wait_until_registered(url, token, hostname)
        if registered:
            renewal = "Renouvellement automatique AUTORISÉ." if allow_renewal else "Renouvellement automatique non autorisé."
            return {"ok": True, "registered": True,
                    "message": f"Terminé : « {hostname} » est enregistré dans CertHelm et actif. {renewal}"}
        return {"ok": True, "registered": False,
                "message": f"Agent installé et démarré, mais « {hostname} » n'est pas encore visible dans CertHelm. "
                           f"Consultez {os.path.join(install_dir, 'agent.log')} ; le premier scan peut prendre "
                           "quelques instants."}

    def uninstall(self, install_dir=DEFAULT_INSTALL_DIR):
        if not is_admin():
            raise InstallError("Droits administrateur requis : relancez l'installeur en tant qu'administrateur.")
        self.log("Arrêt et suppression de la tâche Windows...")
        _run(["schtasks", "/end", "/tn", TASK_NAME], check=False)
        _run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], check=False)
        _run(["taskkill", "/F", "/IM", AGENT_EXE_NAME], check=False)
        try:
            os.remove(startup_script_path())
        except OSError:
            pass
        return (f"Agent arrêté et désinstallé. Le dossier {install_dir} (configuration et journal) a été conservé ; "
                "supprimez-le si vous n'en avez plus besoin. Pensez aussi à retirer le serveur dans CertHelm "
                "(Agents & Découverte → Réglages → Supprimer).")


# ============================== command line ==============================

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Installeur de l'agent CertHelm")
    p.add_argument("--controller-url", help="Adresse de CertHelm, ex. http://10.0.0.5:8765")
    p.add_argument("--token", help="Jeton affiché dans CertHelm (Paramètres → Agents & Découverte)")
    p.add_argument("--hostname", help="Nom de ce serveur dans CertHelm (défaut : nom de la machine)")
    p.add_argument("--mode", choices=MODES, default="schedule")
    p.add_argument("--allow-renewal", action="store_true",
                   help="Autoriser CertHelm à renouveler les certificats de ce serveur")
    p.add_argument("--install-dir", default=DEFAULT_INSTALL_DIR)
    p.add_argument("--silent", action="store_true", help="Installation sans interface (journal : install.log)")
    p.add_argument("--uninstall", action="store_true", help="Désinstaller l'agent")
    return p.parse_args(argv)


def run_silent(args):
    try:
        os.makedirs(args.install_dir, exist_ok=True)
        log_file = open(os.path.join(args.install_dir, "install.log"), "a", encoding="utf-8", buffering=1)
    except OSError:  # e.g. not administrator yet: still leave a trace somewhere readable
        import tempfile
        log_file = open(os.path.join(tempfile.gettempdir(), "CertHelmAgent_install.log"), "a",
                        encoding="utf-8", buffering=1)

    def log(message):
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")

    installer = Installer(log)
    try:
        if args.uninstall:
            log(installer.uninstall(args.install_dir))
            return 0
        if not args.controller_url or not args.token:
            log("--controller-url et --token sont requis avec --silent.")
            return 2
        result = installer.install(args.controller_url, args.token, args.hostname, args.mode,
                                   args.allow_renewal, args.install_dir)
        log(result["message"])
        return 0 if result["registered"] is not False else 3
    except InstallError as e:
        log(f"ÉCHEC : {e}")
        return 1
    except Exception as e:
        log(f"ÉCHEC inattendu : {e}")
        return 1
    finally:
        log_file.close()


# ============================== window ==============================

def run_gui(args):
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title("CertHelm - Installation de l'agent")
    root.configure(bg=BG)
    root.resizable(False, False)
    messages = queue.Queue()
    existing = read_existing_config(args.install_dir)

    def label(text, fg=TEXT, font=("Segoe UI", 9), pady=(8, 2), **kw):
        widget = tk.Label(root, text=text, bg=BG, fg=fg, font=font, anchor="w", justify="left", **kw)
        widget.pack(fill="x", padx=28, pady=pady)
        return widget

    def entry(value="", show=None):
        e = tk.Entry(root, bg=CARD, fg=BRIGHT, insertbackground=BRIGHT, relief="flat", font=("Segoe UI", 10),
                     highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT, show=show)
        e.insert(0, value)
        e.pack(fill="x", padx=28, ipady=4)
        return e

    def button(text, command, bg=CARD, fg=BRIGHT, pady=(6, 0), ipady=5):
        b = tk.Button(root, text=text, command=command, bg=bg, fg=fg, relief="flat",
                      font=("Segoe UI", 9, "bold"), activebackground=BORDER, activeforeground=BRIGHT,
                      cursor="hand2")
        b.pack(fill="x", padx=28, pady=pady, ipady=ipady)
        return b

    label("Configuration de l'agent", BRIGHT, ("Segoe UI", 15, "bold"), pady=(16, 0))
    label("Ces informations se trouvent dans CertHelm → Paramètres → Agents & Découverte.", MUTED, pady=(2, 2),
          wraplength=480)
    state_label = label("", MUTED, pady=(2, 0), wraplength=480)

    label("Adresse de CertHelm")
    url_entry = entry(args.controller_url or existing.get("controller_url", ""))
    label("Jeton")
    token_entry = entry(args.token or "", show="•")
    show_token = tk.BooleanVar(value=False)
    tk.Checkbutton(root, text="Afficher le jeton", variable=show_token, bg=BG, fg=MUTED, selectcolor=CARD,
                   activebackground=BG, activeforeground=BRIGHT, font=("Segoe UI", 8),
                   command=lambda: token_entry.config(show="" if show_token.get() else "•")
                   ).pack(anchor="w", padx=24)
    label("Nom de ce serveur dans CertHelm", pady=(4, 2))
    host_entry = entry(args.hostname or existing.get("hostname") or socket.gethostname())

    result_label = label("", MUTED, pady=(6, 0), wraplength=480)
    test_button = button("Tester la connexion et le jeton", lambda: start(test_only=True), pady=(6, 12))
    tk.Frame(root, bg=BORDER, height=1).pack(fill="x", padx=28)

    label("Comment lancer l'agent ?", BRIGHT, ("Segoe UI", 10, "bold"), pady=(10, 4))
    mode_var = tk.StringVar(value=args.mode)
    for value, text in (
        ("schedule", "Tâche en arrière-plan — tourne en continu, démarre avec Windows, pilotable depuis CertHelm "
                     "(recommandé pour un serveur)"),
        ("tray", "Icône barre des tâches — visible en session (poste de travail)"),
        ("manual", "Rien — je lancerai l'agent moi-même"),
    ):
        tk.Radiobutton(root, text=text, variable=mode_var, value=value, bg=BG, fg=TEXT, selectcolor=CARD,
                       activebackground=BG, activeforeground=BRIGHT, font=("Segoe UI", 9), wraplength=470,
                       justify="left", anchor="w").pack(fill="x", padx=28, pady=1)

    tk.Frame(root, bg=BORDER, height=1).pack(fill="x", padx=28, pady=(10, 0))
    allow_var = tk.BooleanVar(value=args.allow_renewal or existing.get("allow_cert_management") is True)
    tk.Checkbutton(root, text="Autoriser CertHelm à renouveler les certificats de ce serveur (génère une nouvelle "
                              "clé et remplace le certificat installé)",
                   variable=allow_var, bg=BG, fg=TEXT, selectcolor=CARD, activebackground=BG,
                   activeforeground=BRIGHT, font=("Segoe UI", 9), wraplength=470, justify="left",
                   anchor="w").pack(fill="x", padx=28, pady=(8, 0))

    install_button = button("Installer", lambda: start(test_only=False), ACCENT, "#ffffff", (14, 4), 7)
    uninstall_button = button("Désinstaller l'agent de ce serveur", lambda: confirm_uninstall(), CARD, MUTED, (0, 16), 3)

    def refresh_state():
        if not sys.platform.startswith("win"):
            return
        state = task_state()
        if state:
            state_label.config(text=f"État actuel : agent installé (tâche « {TASK_NAME} » : {state}).", fg=OK)
        elif read_existing_config(args.install_dir):
            state_label.config(text="État actuel : configuration présente, tâche en arrière-plan absente.", fg=WARN)
        else:
            state_label.config(text="État actuel : agent non installé sur ce serveur.", fg=MUTED)
        if not is_admin():
            state_label.config(text=state_label.cget("text") + "  Lancez l'installeur en administrateur pour installer.",
                               fg=WARN)

    def set_busy(busy):
        for b in (test_button, install_button, uninstall_button):
            b.config(state="disabled" if busy else "normal")

    def show(text, color=MUTED):
        result_label.config(text=text, fg=color)

    def worker(action):
        try:
            messages.put(("done", action()))
        except InstallError as e:
            messages.put(("error", str(e)))
        except Exception as e:  # never leave the window stuck on "en cours"
            messages.put(("error", f"Erreur inattendue : {e}"))

    def start(test_only):
        url, token, host = url_entry.get(), token_entry.get(), host_entry.get().strip() or socket.gethostname()
        set_busy(True)
        show("Vérification de CertHelm...", MUTED)
        installer = Installer(lambda m: messages.put(("log", m)))
        if test_only:
            def action():
                check = verify_controller(url, token, host)
                if not check["token_checked"]:
                    return ("warn", "CertHelm est joignable (version ancienne : jeton non vérifiable).")
                seen = "déjà enregistré" if check["registered"] else "pas encore enregistré"
                return ("ok", f"Connexion et jeton valides. Ce serveur est {seen} dans CertHelm.")
        else:
            def action():
                result = installer.install(url, token, host, mode_var.get(), allow_var.get(), args.install_dir)
                return ("ok" if result["registered"] is not False else "warn", result["message"])
        threading.Thread(target=worker, args=(action,), daemon=True).start()

    def confirm_uninstall():
        if not messagebox.askyesno("Désinstaller", "Arrêter et désinstaller l'agent CertHelm de ce serveur ?"):
            return
        set_busy(True)
        show("Désinstallation...", MUTED)
        installer = Installer(lambda m: messages.put(("log", m)))
        threading.Thread(target=worker, args=(lambda: ("ok", installer.uninstall(args.install_dir)),),
                         daemon=True).start()

    def pump():
        try:
            while True:
                kind, payload = messages.get_nowait()
                if kind == "log":
                    show(payload, MUTED)
                elif kind == "error":
                    show(payload, BAD)
                    set_busy(False)
                    refresh_state()
                else:
                    level, text = payload
                    show(text, OK if level == "ok" else WARN)
                    set_busy(False)
                    refresh_state()
        except queue.Empty:
            pass
        root.after(150, pump)

    refresh_state()
    pump()
    root.update_idletasks()
    w, h = max(root.winfo_reqwidth(), 520), root.winfo_reqheight()
    x = (root.winfo_screenwidth() - w) // 2
    y = max(0, (root.winfo_screenheight() - h) // 2 - 20)
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.mainloop()


def main():
    if sys.stderr is None:  # windowed exe: argparse would crash trying to print a usage error
        sys.stderr = open(os.devnull, "w")
    args = parse_args()
    if args.silent or args.uninstall:
        sys.exit(run_silent(args))
    run_gui(args)


if __name__ == "__main__":
    main()
