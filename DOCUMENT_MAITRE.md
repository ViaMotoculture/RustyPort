# RustyPort

## Projet

RustyPort est un utilitaire Windows en Rust et Win32. Il inventorie les ports
TCP en écoute et les sockets UDP du PC avec leur adresse, leur PID et leur
processus. La liste se relève automatiquement, se filtre par texte et par
niveau, et se trie en cliquant sur les colonnes. Elle affiche la durée
d'observation de chaque port et l'âge du processus si Windows le fournit.
Le tableau indique les connexions TCP établies au dernier relevé et les
nouvelles connexions observées sur 60 secondes. On peut sélectionner plusieurs
lignes et consulter les détails ou lancer une recherche web depuis la ligne visée.
L'intervalle se règle de 250 ms à 10 s, avec 500 ms par défaut. La croix
masque la fenêtre et la surveillance continue dans la zone de notification.
Un nouveau lancement réaffiche l'instance existante.

La fenêtre regroupe la cadence et la durée de surveillance dans le bandeau.
Le graphique affiche les repères temporels et les courbes utiles à la
sélection. L'inventaire associe une teinte à chaque niveau. Le volet
« Historique » se replie et indique l'espace disque occupé.

## Structure

- `src/main.rs` gère l'interface native et `src/ui.rs` en définit la
  disposition et le thème. `src/ports.rs` lit les tables de ports, les
  processus et les services Windows.
- `src/risk.rs` décrit les niveaux d'exposition. `src/table_view.rs` gère
  l'affichage, le filtrage et le tri des lignes.
- `src/monitor.rs` relève les octets des interfaces actives avec IP Helper.
  `src/chart.rs` dessine les débits des interfaces ou les connexions TCP
  des ports sélectionnés. `src/archive.rs` gère la lecture par fenêtres
  de 60 secondes, les relevés temporaires sur disque et les exports CSV.
- `src/firewall.rs` gère le blocage entrant et le retrait d'une règle RustyPort
  via le Pare-feu Windows, ainsi que l'expiration des règles temporaires.
  Ces actions demandent une élévation UAC.
- `src/duration_dialog.rs` recueille la durée au moment d'une action
  temporaire. `src/stop_job.rs` traite l'arrêt après élévation si Windows
  refuse l'accès au premier essai.
- `src/relaunch.rs` surveille les relances des applications sélectionnées.
  `src/tray.rs` gère la zone de notification. L'icône native vient de
  `assets/RustyPort.ico`.
- `docs/Protocoles.txt` explique les ports et les actions de l'application.
- `ROADMAP.md` fixe les objectifs. `VALIDATION_LOG.md` consigne les essais.
- `tools/pre-push-audit.ps1` recherche des motifs sensibles avant publication.

## État et compilation

Le projet s'appelle RustyPort. La branche de référence est `main` dans
`RustyPort/OPEN-VIA-PORT`. Le nom `kinowill/RustyPort` reste
à appliquer dans les paramètres GitHub. L'exécutable est produit par Cargo.

```powershell
cargo test --locked
cargo build --release --locked
```

Le binaire Cargo est `target/release/rustyport.exe`. Pour intégrer l'icône
de l'Explorateur à un binaire de livraison, copier le binaire puis exécuter
`target/release/rustyport.exe --embed-icon <copie.exe>` sur la copie.
L'application fonctionne
sans élévation pour la lecture et demande les droits nécessaires aux actions
Windows qui les exigent. Le projet est un utilitaire de poste de travail.

## Décisions

- Le dépôt versionne les sources et le verrou des dépendances. `RustyPort.exe`
  à la racine reste le lanceur local généré.
- Utiliser les compteurs natifs des interfaces hors bouclage et les états
  TCP disponibles sans élévation. Les débits concernent les interfaces et
  l'activité UDP par port est indiquée comme indisponible.
- Le niveau est une indication locale. Un port identifié comme sensible et
  lié au réseau prime sur la reconnaissance du processus. Le pare-feu et
  l'accessibilité depuis Internet demandent leur propre vérification.
- Le niveau et les droits d'arrêt sont évalués séparément. Les actions
  de groupe demandent une confirmation et regroupent les processus et règles
  de pare-feu identiques. Les processus protégés sont écartés de l'arrêt.
- La recherche web transmet le nom affiché de l'exécutable, le port et le
  protocole quand l'utilisateur la lance depuis le menu.
- La lecture de l'historique charge une page à la fois. Les fichiers
  temporaires sont créés après activation de l'archivage et libérés quand
  RustyPort quitte. Les exports écrits à
  la demande sont des fichiers CSV autonomes.
- Un blocage temporaire réserve une tâche d'expiration Windows avant
  d'ajouter sa règle entrante. Le retrait RustyPort cible les règles de
  l'application pour le port et le protocole demandés, y compris les règles
  créées avant le renommage. Les identifiants Windows utilisés pour
  retrouver l'instance active restent compatibles avec l'ancienne version.
- La surveillance des relances se borne au chemin exact d'une application
  de l'utilisateur. Une relance est arrêtée au relevé suivant. Elle prend
  fin à l'échéance, sur annulation ou quand RustyPort quitte réellement.
