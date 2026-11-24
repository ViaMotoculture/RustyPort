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

## 2026-11-24 - Actions groupées et historique

- Windows, Rust 1.99.0, cible `x86_64-pc-windows-gnu`. Les 13 tests
  `cargo test --locked`, `cargo check --all-targets --locked` et
  `cargo build --release --locked` ont réussi.
- La liste Win32 a conservé la sélection groupée au tri et traité Ctrl+A,
  Ctrl+clic et le glisser. Les essais ont couvert les nouvelles connexions
  TCP, les repères de niveau, le dialogue de durée et la requête web encodée.
- La pause a gardé le relevé affiché pendant la collecte. La lecture d'une
  page ancienne, l'export CSV borné et la suppression des deux fichiers
  temporaires à la fermeture de leurs handles ont été vérifiés. L'interface
  native démarre à 500 ms et ouvre les fichiers d'archive uniquement après
  activation.
- Le binaire a rejeté un lot d'arrêt mal formé avant d'agir et a arrêté
  deux processus de test après validation de leur identité. L'invite UAC
  réelle et l'expiration d'une règle réelle de pare-feu restent à vérifier.
- Windows a signalé VPBA en écoute sur `127.0.0.1:8514/TCP` et une
  requête locale a reçu HTTP 200. L'Explorateur a trouvé le groupe d'icônes
  dans le binaire livré. Son SHA-256 est
  `83180C58851738A363FB446DF5F8C0BAD71D26DB51B23051DDE650E39E544C6B`.

## 2026-11-24 - Publication et disposition néo-rétro

- Les trois versions locales initiales ont été publiées sur `main` sous
  le compte GitHub `RustyPort` jusqu'au commit `516c1a3`. Les
  empreintes des arborescences correspondent aux versions locales.
- Les 13 tests, `cargo check --all-targets --locked` et
  `cargo build --release --locked` ont réussi sous Windows.
- Une instance de test hors écran a vérifié l'affichage à 1100 × 760 et
  900 × 630, le filtre, le volet d'historique, deux courbes TCP en pause
  et le détail au survol. Ouvrir le volet a laissé l'archivage désactivé.
- Windows a trouvé le groupe d'icônes dans l'exécutable de livraison.
  SHA-256
  `B5674B9C15A5855D6BAA33EA65F449DFF6EF29EA0656A7AC532A22BA8D752C69`.
