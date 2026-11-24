# OpenPort

## Projet

OpenPort est un utilitaire Windows en Rust et Win32. Il inventorie les ports
TCP en écoute et les sockets UDP du PC avec leur adresse, leur PID et leur
processus. La liste se filtre et se rafraîchit à la demande.

## Structure

- `src/main.rs` gère l'interface native. `src/ports.rs` interroge Windows.
- `src/firewall.rs` gère le blocage entrant et le retrait d'une règle OpenPort
  via le Pare-feu Windows. Ces deux actions demandent une élévation UAC.
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
