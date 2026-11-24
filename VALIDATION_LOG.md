# Journal de validation OpenPort

## 2026-11-24 - État initial

- Windows, Rust 1.99.0, cible `x86_64-pc-windows-gnu`. `cargo test --locked`
  a réussi avec 3 tests sur la base importée.
- Windows a renvoyé les écoutes TCP et les sockets UDP de test en IPv4 et
  IPv6. L'arrêt du processus de test a libéré sa socket et l'identité périmée
  a été rejetée. Les scripts de pare-feu ont été analysés par PowerShell.
- L'essai du pare-feu porte sur la syntaxe. La modification de règles demande
  une recette sur un poste Windows avec droits d'administration.

## 2026-11-24 - Tableau de surveillance et actions

- Windows, Rust 1.99.0, cible `x86_64-pc-windows-gnu`. Exécutés avec les
  dépendances présentes en cache. `cargo check --all-targets --locked`,
  `cargo test --locked` (10 tests) et `cargo build --release --locked`
  ont réussi.
- L'interface Win32 de test a relevé l'ouverture et la fermeture d'une
  connexion, inversé le tri en gardant la sélection, affiché un échantillon
  au survol et appliqué un changement de cadence.
- La surveillance des relances a arrêté un exécutable de test du même
  compte. Une règle expirée et un chemin différent ont laissé le processus
  actif. Les règles concernant DHCP et le service d'heure reposent sur le
  PID renvoyé par le gestionnaire de services Windows.
- Sur le binaire release, la fenêtre a affiché les compteurs d'interfaces
  Windows et chargé l'icône native. Fermer a masqué ou réduit la fenêtre
  en gardant le processus actif. La commande « Quitter » l'a terminé.
- Exécutable local contrôlé par SHA-256
  `9724927265C5E31508FD1884848077EBAB8C0EF1D1B266DFE593DC6D6627D35F`.
- PowerShell a analysé les commandes de blocage, de retrait et de blocage
  temporaire. L'expiration d'une règle réelle avec le Planificateur de
  tâches reste à tester avec élévation UAC. Les outils de formatage
  Rustfmt et Clippy sont absents de cette toolchain.
- La copie Git de publication est dans `.publication` dans l'espace local.
  La tentative de push à blanc a échoué à la connexion HTTPS vers GitHub.
