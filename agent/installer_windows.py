#!/usr/bin/env python3
"""
CertHelm - installeur graphique pour l'agent de decouverte de
certificats (Windows).

Renseigne agent_config.json a cote de CertHelmAgent.exe, teste la
connexion au controleur, et propose d'automatiser le lancement :
- tache planifiee Windows (scan quotidien, sans interface)
- icone barre des taches (scan automatique, visible en session)
- ou rien (lancement manuel)

Aucune dependance externe - tkinter fait partie de la bibliotheque standard.
"""

import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import tkinter as tk
from tkinter import filedialog, messagebox

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

AGENT_EXE = os.path.join(APP_DIR, "CertHelmAgent.exe")
TASK_NAME = "CertHelmAgent"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # keep powershell/schtasks from flashing a console

BG = "#121316"
CARD = "#1a1c20"
BORDER = "#2a2d33"
TEXT = "#d1d5db"
BRIGHT = "#ffffff"
MUTED = "#8b93a1"
ACCENT = "#009FDF"


class InstallerApp:
    def __init__(self, root):
        self.root = root
        root.title("CertHelm - Installation de l'agent")
        root.configure(bg=BG)
        root.resizable(False, False)
        self._build_ui()
        # Taille calculee d'apres le contenu (dependante du zoom Windows) :
        # une taille fixe coupait le bouton Installer.
        root.update_idletasks()
        w, h = root.winfo_reqwidth(), root.winfo_reqheight()
        x = (root.winfo_screenwidth() - w) // 2
        y = max(0, (root.winfo_screenheight() - h) // 2 - 20)
        root.geometry(f"{w}x{h}+{x}+{y}")

    def _field_label(self, parent, text):
        tk.Label(parent, text=text, bg=BG, fg=TEXT, font=("Segoe UI", 9),
                  anchor="w").pack(fill="x", padx=28, pady=(8, 2))

    def _entry(self):
        return tk.Entry(self.root, bg=CARD, fg=BRIGHT, insertbackground=BRIGHT,
                         relief="flat", font=("Segoe UI", 10),
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT)

    def _build_ui(self):
        tk.Label(self.root, text="Configuration de l'agent", bg=BG, fg=BRIGHT,
                  font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=28, pady=(16, 0))
        tk.Label(self.root,
                  text="Ces informations se trouvent dans CertHelm → Paramètres → Agents & Découverte.",
                  bg=BG, fg=MUTED, font=("Segoe UI", 9), wraplength=480,
                  justify="left").pack(anchor="w", padx=28, pady=(2, 2))

        self._field_label(self.root, "URL du contrôleur (controller_url)")
        self.url_entry = self._entry()
        self.url_entry.pack(fill="x", padx=28, ipady=4)

        self._field_label(self.root, "Token")
        self.token_entry = self._entry()
        self.token_entry.pack(fill="x", padx=28, ipady=4)

        self._field_label(self.root, "Nom de ce serveur (hostname)")
        self.hostname_entry = self._entry()
        self.hostname_entry.insert(0, socket.gethostname())
        self.hostname_entry.pack(fill="x", padx=28, ipady=4)

        self.status_label = tk.Label(self.root, text="", bg=BG, fg=MUTED,
                                      font=("Segoe UI", 9), wraplength=480, justify="left")
        self.status_label.pack(fill="x", padx=28, pady=(6, 0))

        tk.Button(self.root, text="Tester la connexion", command=self.test_connection,
                   bg=CARD, fg=BRIGHT, relief="flat", font=("Segoe UI", 9, "bold"),
                   activebackground=BORDER, activeforeground=BRIGHT,
                   cursor="hand2").pack(fill="x", padx=28, pady=(6, 12), ipady=5)

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=28)

        tk.Label(self.root, text="Comment lancer l'agent ?", bg=BG, fg=BRIGHT,
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=28, pady=(10, 4))

        self.mode_var = tk.StringVar(value="schedule")
        modes = [
            ("schedule", "Tâche en arrière-plan — tourne en continu sans interface, pilotable depuis CertHelm (recommandé pour un serveur)"),
            ("tray", "Icône barre des tâches — scan automatique, visible en session (poste de travail)"),
            ("manual", "Rien — je lancerai l'agent moi-même"),
        ]
        for value, text in modes:
            tk.Radiobutton(self.root, text=text, variable=self.mode_var, value=value,
                            bg=BG, fg=TEXT, selectcolor=CARD, activebackground=BG,
                            activeforeground=BRIGHT, font=("Segoe UI", 9), wraplength=470,
                            justify="left", anchor="w").pack(fill="x", padx=28, pady=1)

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=28, pady=(10, 0))
        # Off by default: a server's administrator has to opt in explicitly.
        self.allow_cert_var = tk.BooleanVar(value=False)
        tk.Checkbutton(self.root,
                        text="Autoriser CertHelm à renouveler les certificats de ce serveur "
                             "(génère une nouvelle clé et remplace le certificat installé)",
                        variable=self.allow_cert_var, bg=BG, fg=TEXT, selectcolor=CARD,
                        activebackground=BG, activeforeground=BRIGHT, font=("Segoe UI", 9),
                        wraplength=470, justify="left", anchor="w").pack(fill="x", padx=28, pady=(8, 0))

        tk.Button(self.root, text="Installer", command=self.install,
                   bg=ACCENT, fg="#ffffff", relief="flat", font=("Segoe UI", 10, "bold"),
                   activebackground="#0077b6", activeforeground="#ffffff",
                   cursor="hand2").pack(fill="x", padx=28, pady=(14, 16), ipady=7)

    def test_connection(self):
        url = self.url_entry.get().strip().rstrip("/")
        if not url:
            self.status_label.config(text="Renseigne d'abord l'URL du contrôleur.", fg="#f59e0b")
            return
        try:
            with urllib.request.urlopen(url + "/agent/ping", timeout=5) as resp:
                if resp.status == 200:
                    self.status_label.config(text="Connexion au contrôleur réussie.", fg="#10b981")
                else:
                    self.status_label.config(text=f"Réponse inattendue du serveur: {resp.status}", fg="#ef4444")
        except urllib.error.URLError as e:
            self.status_label.config(text=f"Impossible de joindre le contrôleur: {e.reason}", fg="#ef4444")
        except Exception as e:
            self.status_label.config(text=f"Erreur: {e}", fg="#ef4444")

    def install(self):
        url = self.url_entry.get().strip()
        token = self.token_entry.get().strip()
        hostname = self.hostname_entry.get().strip() or socket.gethostname()

        if not url or not token:
            messagebox.showerror("Champs manquants", "L'URL du contrôleur et le token sont requis.")
            return

        self.agent_exe = AGENT_EXE
        if not os.path.exists(self.agent_exe):
            messagebox.showwarning(
                "Agent introuvable",
                "CertHelmAgent.exe n'est pas à côté de cet installeur.\n\n"
                "Sélectionne-le dans la fenêtre suivante."
            )
            chosen = filedialog.askopenfilename(
                title="Sélectionner CertHelmAgent.exe",
                filetypes=[("CertHelm Agent", "*.exe"), ("Tous les fichiers", "*.*")]
            )
            if not chosen:
                return
            self.agent_exe = os.path.abspath(chosen)

        # L'agent lit agent_config.json a cote de son propre exe.
        agent_dir = os.path.dirname(self.agent_exe)
        config_path = os.path.join(agent_dir, "agent_config.json")

        config = {"controller_url": url, "token": token, "hostname": hostname}
        if self.allow_cert_var.get():
            config["allow_cert_management"] = True
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'écrire agent_config.json:\n{e}")
            return

        mode = self.mode_var.get()
        try:
            if mode == "schedule":
                self._setup_scheduled_task()
                # Demarre tout de suite : sans ca le serveur n'apparait dans
                # CertHelm qu'apres le prochain redemarrage.
                self._run_quiet(["schtasks", "/run", "/tn", TASK_NAME])
                messagebox.showinfo(
                    "Installation terminée",
                    "Configuration enregistrée. L'agent tourne maintenant en arrière-plan "
                    "(tâche « CertHelmAgent », compte SYSTEM, relancée à chaque démarrage de Windows).\n\n"
                    "Le serveur apparaît dans CertHelm → Agents & Découverte dans quelques "
                    "secondes (rafraîchis la page). Journal : agent.log à côté de l'agent."
                )
            elif mode == "tray":
                # Un seul agent par machine : la tache de fond ferait doublon avec l'icone.
                subprocess.run(["schtasks", "/end", "/tn", TASK_NAME], capture_output=True, creationflags=NO_WINDOW)
                subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], capture_output=True, creationflags=NO_WINDOW)
                self._setup_tray_startup()
                subprocess.Popen([self.agent_exe, "--tray"],
                                 creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
                messagebox.showinfo(
                    "Installation terminée",
                    "Configuration enregistrée. L'icône barre des tâches est lancée maintenant "
                    "(près de l'horloge) et se relancera à chaque connexion Windows.\n\n"
                    "Le serveur apparaît dans CertHelm dans quelques secondes."
                )
            else:
                messagebox.showinfo(
                    "Configuration enregistrée",
                    f"agent_config.json a été créé dans:\n{agent_dir}\n\n"
                    "Lance CertHelmAgent.exe manuellement quand tu veux scanner."
                )
        except Exception as e:
            messagebox.showerror(
                "Configuration enregistrée, automatisation échouée",
                f"agent_config.json a bien été créé, mais l'étape d'automatisation a échoué :\n{e}"
            )

    @staticmethod
    def _run_quiet(cmd):
        """Runs a command without flashing a console; raises with the real error text."""
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or f"code {result.returncode}").strip())

    def _setup_scheduled_task(self, task_name=TASK_NAME):
        """Registers the agent as a background task: started at boot, run as SYSTEM
        (needed later to write into the machine certificate store), never killed
        after 72h (the Task Scheduler default), restarted if it ever crashes."""
        exe = self.agent_exe.replace("'", "''")
        workdir = os.path.dirname(self.agent_exe).replace("'", "''")
        script = (
            "$ErrorActionPreference='Stop';"
            f"$a=New-ScheduledTaskAction -Execute '{exe}' -Argument '--daemon' -WorkingDirectory '{workdir}';"
            "$t=New-ScheduledTaskTrigger -AtStartup;"
            "$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 "
            "-RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries "
            "-DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;"
            "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
            f"Register-ScheduledTask -TaskName '{task_name}' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null"
        )
        # Stop a previous instance first so the exe isn't locked and the new task starts clean.
        subprocess.run(["schtasks", "/end", "/tn", task_name], capture_output=True, creationflags=NO_WINDOW)
        self._run_quiet(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                         "-Command", script])

    def _setup_tray_startup(self):
        startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        bat_path = os.path.join(startup_dir, "CertHelmAgentTray.bat")
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write(f'@echo off\nstart "" "{self.agent_exe}" --tray\n')


def main():
    root = tk.Tk()
    InstallerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
