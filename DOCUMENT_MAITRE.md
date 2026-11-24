# OpenPort

## Projet

OpenPort est un utilitaire Windows en Rust et Win32. Il inventorie les ports
TCP en écoute et les sockets UDP du PC avec leur adresse, leur PID et leur
processus. La liste se relève automatiquement, se filtre par texte et par
niveau, et se trie en cliquant sur les colonnes. Elle affiche la durée
d'observation de chaque port et l'âge du processus si Windows le fournit.
Le tableau indique les connexions TCP établies au dernier relevé.
L'intervalle se règle de 250 ms à 10 s. La croix masque la fenêtre et la
surveillance continue dans la zone de notification.

## Structure

- `src/main.rs` gère l'interface native. `src/ports.rs` lit les tables de
  ports, les processus et les services Windows.
- `src/risk.rs` décrit les niveaux d'exposition. `src/table_view.rs` gère
  l'affichage, le filtrage et le tri des lignes.
- `src/monitor.rs` relève les octets des interfaces actives avec IP Helper.
  `src/chart.rs` dessine les débits reçus et envoyés sur 60 secondes.
- `src/firewall.rs` gère le blocage entrant et le retrait d'une règle OpenPort
  via le Pare-feu Windows, ainsi que l'expiration des règles temporaires.
  Ces actions demandent une élévation UAC.
- `src/relaunch.rs` surveille les relances des applications sélectionnées.
  `src/tray.rs` gère la zone de notification. L'icône native vient de
  `assets/OpenPort.ico`.
- `docs/Protocoles.txt` explique les ports et les actions de l'application.
- `ROADMAP.md` fixe les objectifs. `VALIDATION_LOG.md` consigne les essais.
- `tools/pre-push-audit.ps1` recherche des motifs sensibles avant publication.

## État et compilation

Le dépôt de référence est `RustyPort/OPEN-VIA-PORT`, branche `main`.
Avant l'initialisation du dépôt, OpenPort était fourni sous forme d'un
exécutable local et de ses sources. L'exécutable est produit par Cargo.

```powershell
cargo test --locked
cargo build --release --locked
```

Le binaire compilé est `target/release/openport.exe`. L'application fonctionne
sans élévation pour la lecture et demande les droits nécessaires aux actions
Windows qui les exigent. Le projet est un utilitaire de poste de travail.

## Décisions

- Le dépôt versionne les sources et le verrou des dépendances. `OpenPort.exe`
  à la racine reste le lanceur local généré.
- Utiliser les compteurs natifs des interfaces hors bouclage et les états
  TCP disponibles sans élévation. Les débits concernent les interfaces et
  l'activité UDP par port est indiquée comme indisponible.
- Le niveau est une indication locale. Un port identifié comme sensible et
  lié au réseau prime sur la reconnaissance du processus. Le pare-feu et
  l'accessibilité depuis Internet demandent leur propre vérification.
- Un blocage temporaire réserve une tâche d'expiration Windows avant
  d'ajouter sa règle entrante. Le retrait OpenPort cible les règles de
  l'application pour le port et le protocole demandés.
- La surveillance des relances se borne au chemin exact d'une application
  de l'utilisateur. Une relance est arrêtée au relevé suivant. Elle prend
  fin à l'échéance, sur annulation ou quand OpenPort quitte réellement.
