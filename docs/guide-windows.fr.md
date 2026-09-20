# Guide pas à pas — CertHelm sur un laptop Windows

Ce guide décrit, étape par étape, l'installation de CertHelm sur un poste Windows vierge jusqu'à la remontée des certificats d'un premier serveur.
Durée estimée : 15 à 30 minutes. Toutes les commandes s'exécutent dans **PowerShell**.

> Ouvrir PowerShell : touche **Windows**, tapez `PowerShell`, Entrée.
> Les étapes indiquées **(administrateur)** requièrent PowerShell ouvert avec des droits élevés : clic droit sur *Windows PowerShell* → **Exécuter en tant qu'administrateur**.

## Sommaire

1. [Prérequis](#1-prérequis)
2. [Récupérer le projet](#2-récupérer-le-projet)
3. [Installer les dépendances](#3-installer-les-dépendances)
4. [Lancer CertHelm](#4-lancer-certhelm)
5. [Connecter votre compte DigiCert](#5-connecter-votre-compte-digicert)
6. [Utiliser les agents](#6-utiliser-les-agents)
7. [Tester le renouvellement (sans risque)](#7-tester-le-renouvellement-sans-risque)
8. [Au quotidien](#8-au-quotidien)
9. [Problèmes fréquents](#9-problèmes-fréquents)

---

## 1. Prérequis

| Il vous faut | Détail | Vérifier |
|---|---|---|
| **Windows 10 ou 11** (64 bits) | L'application de bureau est Windows uniquement. | — |
| **Python 3.10 à 3.12** | Testé avec 3.12. Cochez **« Add python.exe to PATH »** à l'installation. | `python --version` |
| **WebView2 Runtime** | Déjà présent sur Windows 11 et sur les Windows 10 à jour avec Edge. C'est lui qui affiche l'interface. | Si la fenêtre reste blanche, voir [§9](#9-problèmes-fréquents) |
| **Une clé API DigiCert CertCentral** | Dans CertCentral : *Account → API Keys → Add API key* (l'intitulé peut varier selon la version de l'interface). Le compte doit avoir le droit de lire les commandes. | — |
| **Accès Internet** vers `www.digicert.com` (HTTPS) | Pour lire vos commandes. | — |
| **Git** *(facultatif)* | Seulement si vous clonez le dépôt. Sinon téléchargez le ZIP depuis GitHub. | `git --version` |

Installer les prérequis manquants en une commande (Windows 10/11 avec `winget`) :

```powershell
winget install Python.Python.3.12
winget install Microsoft.EdgeWebView2Runtime
winget install Git.Git
```

Fermez puis rouvrez PowerShell après l'installation de Python, puis vérifiez :

```powershell
python --version      # doit afficher Python 3.10, 3.11 ou 3.12
```

## 2. Récupérer le projet

**Avec Git :**

```powershell
cd $HOME\Documents
git clone <URL-de-votre-depot-GitHub> CertHelm
cd CertHelm
```

**Sans Git :** sur GitHub, bouton vert **Code → Download ZIP**, extrayez-le (par ex. dans `Documents\CertHelm`), puis :

```powershell
cd $HOME\Documents\CertHelm
```

Vous devez voir `README.md`, `certhelm\`, `agent\`, `docs\`… :

```powershell
dir
```

## 3. Installer les dépendances

On crée un environnement isolé (`.venv`) pour ne rien mélanger avec le reste de votre Python.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

> **« l'exécution de scripts est désactivée sur ce système »** : tapez d'abord
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` (valable pour cette fenêtre seulement), puis relancez la ligne `Activate.ps1`.

Le début de la ligne doit maintenant afficher `(.venv)`. Puis :

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Cela installe `pywebview`, `keyring`, `cryptography` et `plyer` (1 à 2 minutes).

## 4. Lancer CertHelm

L'application cherche son interface, sa base et sa configuration **dans le dossier courant** : il faut donc se placer dans `certhelm\` avant de la lancer.

```powershell
cd certhelm
python main.py
```

Une fenêtre **CertHelm** s'ouvre. Deux fichiers sont créés dans ce dossier `certhelm\` :

| Fichier | Contenu |
|---|---|
| `workflow.db` | Base locale (notes, affectations, agents, renouvellements…). |
| `config.json` | Réglages non sensibles (seuil d'alerte, SMTP…). |

Ils ne sont **jamais** commités (déjà dans `.gitignore`). Sauvegardez-les si vous tenez à vos données.

Les fois suivantes (pas besoin d'activer l'environnement, on appelle directement son Python) :

```powershell
cd $HOME\Documents\CertHelm\certhelm
..\.venv\Scripts\python.exe main.py
```

## 5. Connecter votre compte DigiCert

1. Dans CertHelm, menu de gauche : **Paramètres**.
2. Section **Connexion DigiCert** : collez votre **clé API**, puis **Enregistrer les Paramètres**.
3. Le tableau de bord (**SSL Dashboard**) se remplit avec vos commandes ; le badge en haut indique *API En Ligne*.

La clé est stockée dans le **Gestionnaire d'identification Windows** (recherchez « Gestionnaire d'identification » dans le menu Démarrer,
puis *Informations d'identification Windows*), jamais dans un fichier. Pour la changer, collez-en une nouvelle.

Facultatif, dans la même page : seuil d'alerte en jours, et **SMTP** pour recevoir des alertes par e-mail (bouton *Tester la configuration SMTP*).

---

### Le centre d'alertes (la cloche)

La cloche en haut à droite regroupe tout ce qui demande votre attention, classé par gravité (critique, avertissement, info), avec des filtres.
Elle se met à jour toute seule chaque minute :

* échéances DigiCert (certificats, validation de domaine, validation d'organisation), **y compris les certificats expirés depuis moins de 30 jours** ;
* certificats trouvés **sur les serveurs** par les agents qui expirent bientôt ou viennent d'expirer ;
* **agents hors ligne** (10 minutes sans signe de vie ; critique après 24 h) ;
* renouvellements en échec ou de statut incertain, et renouvellements réussis (information) ;
* connexion DigiCert impossible (clé API absente ou refusée) et récepteur d'agents non démarré.

Un clic sur une alerte ouvre l'élément concerné. Le nombre rouge indique ce qui demande une action ; « Tout est en ordre » ne s'affiche que si rien n'est à signaler.

## 6. Utiliser les agents

Un **agent** est un petit programme installé sur un serveur (ou sur ce même laptop pour essayer). Il liste les certificats
réellement installés et les envoie à CertHelm. Il n'ouvre aucun port : c'est lui qui appelle votre laptop.

```
   Serveur (agent)  ──────►  Laptop CertHelm (port 8765)
```

### 6.1 Récupérer l'adresse et le jeton

1. CertHelm → **Paramètres** → section **Agents & Découverte**.
2. **controller_url** : l'adresse à donner aux agents, de la forme `http://<IP-du-laptop>:8765`.
   > Sur un PC qui a plusieurs cartes réseau, cette suggestion peut ne pas être celle que vos serveurs peuvent joindre. Vérifiez votre vraie adresse :
   > ```powershell
   > ipconfig
   > ```
   > et prenez l'*Adresse IPv4* de la carte Wi-Fi ou Ethernet connectée. Les serveurs doivent pouvoir joindre cette adresse.
   > Pour un test sur ce même laptop, utilisez `http://127.0.0.1:8765`.
3. **Jeton** : il est affiché masqué. Cliquez **Régénérer le token** : le jeton complet s'affiche **une seule fois** — copiez-le tout de suite.
   (Régénérer invalide l'ancien jeton : les agents déjà installés devront être reconfigurés.)

### 6.2 Autoriser le port sur le poste (pare-feu) (administrateur)

Si les agents sont sur d'**autres machines**, le pare-feu du laptop doit laisser entrer le port `8765`. PowerShell **administrateur** :

```powershell
New-NetFirewallRule -DisplayName "CertHelm agents" -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow -Profile Private -RemoteAddress 10.0.0.0/24
```

Remplacez `10.0.0.0/24` par le réseau de vos serveurs (ne laissez pas ouvert à tout le monde). Pour supprimer la règle plus tard :
`Remove-NetFirewallRule -DisplayName "CertHelm agents"`.

Test depuis le **serveur** (doit répondre `{"status": "ok"}`) — CertHelm doit être lancé sur le laptop :

```powershell
Invoke-WebRequest http://<IP-du-laptop>:8765/agent/ping -UseBasicParsing
```

### 6.3 Essayer l'agent tout de suite, sans rien installer

Sur n'importe quelle machine Windows avec Python (aucune dépendance à installer), depuis le dossier du projet :

```powershell
python agent\certhelm_agent.py --dry-run
```

Il affiche les certificats trouvés dans le magasin Windows **sans rien envoyer**.

Pour l'envoyer réellement à CertHelm, copiez `agent\agent_config.example.json` en `agent\agent_config.json`, remplissez-le, puis :

```powershell
copy agent\agent_config.example.json agent\agent_config.json
notepad agent\agent_config.json
python agent\certhelm_agent.py
```

```json
{
  "controller_url": "http://127.0.0.1:8765",
  "token": "COLLEZ-ICI-LE-JETON",
  "hostname": "mon-laptop",
  "allow_cert_management": false
}
```

Retournez dans CertHelm → **Agents & Découverte** → **Rafraîchir** : votre machine apparaît. Ce mode fait **un seul scan puis s'arrête**.
Pour un agent qui reste en fonctionnement et que CertHelm peut piloter : `python agent\certhelm_agent.py --daemon` (Ctrl+C pour arrêter).
En mode `--daemon` rien ne s'affiche dans la console : tout va dans `agent\agent.log`.

> Point de vigilance : `agent_config.json` contient le jeton : ne le commitez jamais (déjà ignoré par Git).

### 6.4 Installer l'agent sur un serveur Windows (recommandé)

Il faut **un seul fichier** à remettre à l'administrateur du serveur : `CertHelmAgent_Setup.exe` (il embarque l'agent). On le fabrique une fois sur le laptop :

```powershell
pip install -r packaging\requirements-build.txt
powershell -File packaging\build_windows.ps1
```

Il se trouve alors dans `dist\agent\`. (Windows SmartScreen peut avertir : les exécutables ne sont pas signés.)

Sur le **serveur** :

1. Copiez `CertHelmAgent_Setup.exe` où vous voulez sur le serveur (le Bureau convient : l'installeur copie lui-même l'agent dans
   `C:\Program Files\CertHelmAgent` et en réserve l'accès aux administrateurs et à SYSTEM, car l'agent tourne sous SYSTEM).
2. Double-cliquez `CertHelmAgent_Setup.exe` (acceptez la demande d'administrateur).
3. Remplissez :
   * **URL du contrôleur** : `http://<IP-du-laptop>:8765`
   * **Token** : le jeton copié en 6.1
   * **Nom de ce serveur** : pré-rempli avec le nom de la machine
4. Cliquez **Tester la connexion et le jeton** → `Connexion et jeton valides`. Une adresse fausse, un pare-feu ou un jeton refusé donnent un message précis.
5. Choisissez le mode :
   * **Tâche en arrière-plan** *(serveurs — recommandé)* : tourne en continu, démarre avec Windows, pilotable depuis CertHelm.
   * **Icône barre des tâches** *(poste de travail)* : point de couleur près de l'horloge.
   * **Rien** : écrit seulement la configuration.
6. Laissez **décochée** la case *« Autoriser CertHelm à renouveler les certificats de ce serveur »* tant que vous n'avez pas lu
   [renewal.md](renewal.md) (elle sert au renouvellement automatique, voir §7).
7. Cliquez **Installer**. L'installeur copie l'agent, l'enregistre, le démarre, puis **attend que le serveur apparaisse dans CertHelm** et affiche
   `Terminé : « NOM » est enregistré dans CertHelm et actif.` Rien n'est installé si l'adresse ou le jeton est faux.

Vous pouvez relancer l'installeur à tout moment : il affiche l'état actuel, permet de changer l'adresse, le jeton ou l'autorisation de renouvellement, et a un bouton **Désinstaller l'agent de ce serveur**.

Déploiement sans interface (GPO, script) :

```powershell
CertHelmAgent_Setup.exe --silent --controller-url http://<IP-du-laptop>:8765 --token <jeton> --allow-renewal
```

Le résultat est écrit dans `install.log` (code de sortie `0` = enregistré, `1` = échec, `2` = arguments manquants, `3` = installé mais serveur absent de la console).

Vérifier :

```powershell
Get-ScheduledTask CertHelmAgent                                   # doit être « Running »
Get-Content "C:\Program Files\CertHelmAgent\agent.log" -Tail 20   # journal de l'agent
```

Puis dans CertHelm → **Agents & Découverte** → **Rafraîchir** : le serveur apparaît avec un point vert.

### 6.5 Agent Linux / RedHat

Copiez `agent/certhelm_agent.py` et `agent_config.json` sur le serveur (Python 3 et `openssl` suffisent), testez avec `python3 certhelm_agent.py --dry-run`,
puis lancez-le en service systemd. Détails et fichier de service : [agents.md](agents.md#linux--redhat).

### 6.6 Piloter un agent depuis CertHelm

Dans **Agents & Découverte**, sur la ligne de chaque agent :

| Bouton | Effet |
|---|---|
| **Scanner maintenant** | Demande un scan immédiat. L'agent répond sous ~30 secondes et une notification donne le résultat. |
| **Détails** | Nom, système, adresse IP, version, premier contact, dernier scan, dernier signe de vie, autorisation de renouvellement donnée par l'administrateur du serveur, **liste des certificats remontés** (jours restants) et dernières commandes. On y règle aussi la fréquence de scan (1 h à 7 jours) et l'interrupteur **Agent actif** (un agent désactivé ne scanne plus), et on peut **Retirer de la console** le serveur (refusé pendant un renouvellement ; un agent encore en marche se ré-enregistre : désinstallez-le d'abord). |

Les boutons sont **grisés** pour un agent trop ancien (v1). Un agent récent lancé en « un seul scan » garde les boutons actifs mais
**ne répondra pas** (il ne tourne pas en permanence) : la commande passera en échec « Pas de réponse de l'agent » après 10 minutes.
Il faut un agent en mode *Tâche en arrière-plan*, *Icône* ou `--daemon`.
Un agent en continu est **en ligne** s'il a été entendu dans les 3 dernières minutes.

Les deux listes en bas de la page sont le vrai intérêt des agents :

* **Connu de DigiCert mais jamais détecté installé** : certificat émis mais déployé nulle part (risque de panne).
* **Détecté sur un serveur mais inconnu de DigiCert** : autre autorité, certificat auto-signé oublié…

### 6.7 Arrêter ou désinstaller un agent Windows (administrateur)

```powershell
schtasks /end    /tn CertHelmAgent
schtasks /delete /tn CertHelmAgent /f
```

Puis supprimez le dossier de l'agent. En mode icône : supprimez aussi
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CertHelmAgentTray.bat` et quittez l'icône (clic droit → *Quitter*).
Ou relancez `CertHelmAgent_Setup.exe` et cliquez **Désinstaller l'agent de ce serveur** (ou `CertHelmAgent_Setup.exe --uninstall`).
Côté CertHelm, retirez ensuite le serveur : **Agents & Découverte → Détails → Retirer de la console**.

---

## 7. Renouveler un certificat depuis CertHelm

Le renouvellement passe une **vraie commande DigiCert (potentiellement facturée)**. Il n'y a pas de mode simulation : chaque renouvellement commence par une confirmation qui détaille la commande exacte, et rien n'est envoyé avant que vous ayez confirmé.

1. **Agents & Découverte** → section **Certificats installés sur les serveurs — renouvellement** : les certificats qui existent aussi dans votre compte DigiCert ont un bouton **Renouveler**.
2. Cliquez **Renouveler** : la confirmation affiche le produit, la durée, les noms couverts et le numéro de la commande d'origine. Confirmez.
3. Suivez l'avancement dans **Suivi des renouvellements** ; « Voir la requête envoyée à DigiCert » montre la requête (sans la clé privée).

Avant la production, lisez [renewal.md](renewal.md) et faites un premier essai sur l'environnement de démonstration DigiCert
(`https://demo.digicert.com/services/v2`, réglable dans **Paramètres → Renouvellement automatique**) avec un serveur non critique. Chaque serveur doit avoir autorisé
l'opération : case **« Autoriser CertHelm à renouveler »** de l'installeur (sinon le bouton est remplacé par « Non autorisé sur ce serveur »). Le suivi ne progresse que tant que **CertHelm reste ouvert**.

---

## 8. Au quotidien

| Je veux… | Commande / action |
|---|---|
| Relancer l'application | `cd <projet>\certhelm` puis `..\.venv\Scripts\python.exe main.py` |
| Mettre à jour | `git pull` puis `pip install -r requirements.txt` (dans le `.venv`) |
| Sauvegarder mes données | Copier `certhelm\workflow.db` et `certhelm\config.json` |
| Repartir de zéro | Fermer CertHelm, supprimer `workflow.db` et `config.json` |
| Changer la clé API | Paramètres → Connexion DigiCert |
| Lancer les tests automatiques | `pip install cryptography` puis `python tests\run_all.py` (n'appelle jamais DigiCert) |

## 9. Problèmes fréquents

| Symptôme | Cause probable / solution |
|---|---|
| `python` : « commande introuvable » | Python n'est pas dans le PATH : réinstallez en cochant *Add python.exe to PATH*, rouvrez PowerShell. |
| `Activate.ps1` refuse de s'exécuter | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` puis relancer. |
| `pip install` échoue sur `pythonnet` | Utilisez Python 3.12 (ou 3.11) 64 bits ; les toutes dernières versions de Python n'ont parfois pas encore de paquet précompilé. |
| La fenêtre CertHelm reste **blanche** | Installez le **WebView2 Runtime** : `winget install Microsoft.EdgeWebView2Runtime`. |
| Fenêtre vide, ou erreur au sujet de `ui/index.html` | Vous n'avez pas fait `cd certhelm` avant `python main.py`. |
| Badge **Erreur API** / tableau de bord vide | Clé API absente ou invalide, ou pas d'accès à `www.digicert.com` (proxy d'entreprise ?). |
| Console : `Failed to start agent listener on port 8765` | Le port est déjà pris (autre instance de CertHelm ?). Fermez l'autre instance. |
| L'agent n'apparaît pas dans CertHelm | Il n'a jamais tourné (mode « Rien » ou « un seul scan »), mauvaise URL, pare-feu, ou CertHelm fermé. Regardez `agent.log`, testez `…/agent/ping`. |
| `agent.log` : `HTTP 401` / `Unauthorized` | Jeton faux ou régénéré depuis. Réinstallez l'agent avec le nouveau jeton. |
| Boutons **Scanner maintenant** grisés | Agent trop ancien (v1) : réinstallez avec la version actuelle. |
| **Scanner maintenant** finit en « Pas de réponse de l'agent » | L'agent ne tourne pas en continu (mode « un seul scan », service arrêté) : passez en *Tâche en arrière-plan* / `--daemon`. |
| L'installeur dit « refuse ce jeton » | Le jeton a été régénéré dans CertHelm depuis, ou mal copié : copiez le nouveau jeton (Paramètres → Agents & Découverte). |
| L'installeur dit « Impossible de joindre CertHelm » | Mauvaise adresse ou port, CertHelm fermé, ou pare-feu du PC CertHelm (§6.2). |
| SmartScreen bloque les `.exe` | Exécutables non signés : « Informations complémentaires » → « Exécuter quand même », ou signez-les avec votre certificat de code. |

Pour aller plus loin : [architecture](architecture.md) · [agents](agents.md) · [renouvellement](renewal.md) · [sécurité](security.md).
