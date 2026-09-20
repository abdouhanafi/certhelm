# CertHelm

**Gestion du cycle de vie des certificats (CLM) pour DigiCert CertCentral.**
Visualisez tous vos certificats, découvrez ce qui est *réellement* déployé sur vos serveurs, puis renouvelez et installez-les en toute sécurité, depuis une seule application de bureau.

> 🇬🇧 English version: [README.md](README.md) · 📘 **Guide pas à pas Windows** (prérequis, commandes, agents, dépannage) : [docs/guide-windows.fr.md](docs/guide-windows.fr.md)

> **Projet indépendant.** CertHelm n'est ni affilié à DigiCert, Inc., ni approuvé ou parrainé par cette société.
> « DigiCert » est une marque de son propriétaire, citée ici uniquement pour indiquer la compatibilité avec l'API DigiCert CertCentral.

**État : bêta.** La découverte, la supervision et les agents sont couverts par des tests automatisés. Le renouvellement
automatique n'a été exécuté que contre un faux serveur DigiCert : lisez [État du projet](#état-du-projet) avant tout usage réel.

---

## Fonctionnalités

- **Tableau de bord** : toutes vos commandes DigiCert, compte à rebours d'expiration, filtres, export CSV.
- **Pipeline de renouvellement** : suivi de chaque certificat (validation, DNS, commande, installation, vérification) avec relances.
- **Conformité & tendances** : durées de validité et historique des renouvellements construit automatiquement.
- **Alertes** : notifications bureau, e-mails SMTP optionnels, brouillons de messages prêts à envoyer.
- **Inventaire & audit** : domaines, organisations, utilisateurs DigiCert, journal d'audit.
- **Agents & découverte** : des agents légers (Windows / Linux) remontent les certificats *réellement installés*. CertHelm signale
  ce que DigiCert a émis mais qui n'a jamais été déployé, et ce qui tourne en production sans être connu de DigiCert.
- **Pilotage à distance** : « Scanner maintenant », fréquence, activation/désactivation par agent — canal où c'est toujours l'agent qui appelle.
- **Renouvellement automatique** : la clé et le CSR sont créés **sur le serveur** ; CertHelm passe la commande, vérifie le
  certificat émis, puis l'agent l'installe (magasin Windows + bindings IIS, ou fichiers PEM + rechargement du service sous Linux),
  avec retour arrière en cas d'échec. Désactivé par défaut, avec un mode **Simulation** sans aucun effet.

## Démarrage rapide

> Le guide détaillé (chaque commande, pare-feu, installation des agents, dépannage) : [docs/guide-windows.fr.md](docs/guide-windows.fr.md).

Prérequis : Windows 10/11, Python 3.10+.

```powershell
git clone <url-du-depot> certhelm
cd certhelm
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

cd certhelm      # l'application cherche ui/, config.json et workflow.db dans le dossier courant
python main.py
```

1. **Paramètres → Connexion DigiCert** : collez une clé API CertCentral (stockée dans le Gestionnaire d'identification Windows, jamais dans un fichier).
2. Le tableau de bord se remplit.
3. Facultatif : déployez des agents — voir [docs/agents.md](docs/agents.md) (en anglais).

## Renouvellement automatique

| Mode | Effet |
|---|---|
| **Désactivé** | Aucun renouvellement. |
| **Simulation** *(défaut)* | Affiche la commande qui *serait* passée. N'envoie rien, ne contacte aucun agent. |
| **Réel** | Chaîne complète. **Passe une vraie commande DigiCert, potentiellement facturée.** |

Chaque serveur doit en plus autoriser explicitement l'opération : `"allow_cert_management": true` dans son `agent_config.json`.
Détails : [docs/renewal.md](docs/renewal.md).

## Sécurité en bref

- Les clés privées sont générées sur le serveur et **n'en sortent jamais** ; seul le CSR circule.
- Le contrôleur n'envoie jamais de chemin de fichier ni de commande système ; l'agent retrouve lui-même le certificat visé.
- Un agent n'installe qu'un certificat correspondant à la clé qu'il a générée pour ce renouvellement précis.
- Un renouvellement ne peut jamais passer deux commandes ; un résultat ambigu est gelé pour vérification humaine.
- Le canal agent ↔ contrôleur est en **HTTP avec un jeton partagé** : réseau de confiance ou proxy TLS obligatoire.

## État du projet

- Non validé contre le service DigiCert réel (tests uniquement contre un faux serveur local) : essayez d'abord le mode Réel sur
  l'environnement de démonstration DigiCert avec un serveur non critique.
- Non exercé sur de vraies machines : `certreq`, bindings IIS, rechargement d'un vrai nginx/httpd.
- Application de bureau Windows uniquement ; l'agent fonctionne sous Windows et Linux.
- L'interface est aujourd'hui essentiellement en français.

## Structure, compilation, tests

Voir [README.md](README.md) (sections *Project layout*, *Building executables*, *Tests*).

## Licence

[MIT](LICENSE)
