# Journal de validation RustyPort

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
- Windows a confirmé une écoute TCP sur le bouclage et une requête locale
  a reçu HTTP 200. L'Explorateur a trouvé le groupe d'icônes
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

## 2026-11-24 - Tri et survol du graphique

- Le test Win32 vérifie le retour au premier résultat après le tri,
  la sélection conservée et le maintien de la position après un défilement
  lors des relevés automatiques.
- Un test de survol retrouve deux ports sur une même position du graphique.
  Les 14 tests, la vérification de toutes les cibles et la compilation de
  l'exécutable de livraison sous Windows ont réussi.
- Une instance hors écran a vérifié le tri par activité, le retour en tête
  après inversion et le texte de survol pour les courbes superposées et
  les débits globaux. L'en-tête d'activité et sa flèche restent visibles
  à 900 × 630.
- Windows a trouvé le groupe d'icônes dans le binaire de livraison.
  SHA-256
  `592BBB18A024512530C5CB7E4023475625EA7A86DE346CF1686C48AAD2D4EEC2`.

## 2026-11-24 - Renommage en RustyPort

- Les 15 tests, `cargo check --all-targets --locked` et
  `cargo build --release --locked` ont réussi sous Windows.
- Une instance de test hors écran a affiché le titre RustyPort et son icône.
  Le tri, les survols et le volet d'historique ont été vérifiés dans cette
  instance. Windows a trouvé le groupe d'icônes dans `RustyPort.exe`.
- Les commandes de réutilisation et de retrait des anciennes règles de
  pare-feu ont été testées avec des fonctions PowerShell simulées.
- SHA-256 de l'exécutable de livraison
  `9D39D27B546673DFE2E8A4FB94719A652FB71EB38ED8B06014D4A4B56F7DD39C`.
- Le dépôt de référence est désormais `kinowill/RustyPort`.

## 2026-11-24 - Niveaux manuels

- Les 18 tests, `cargo check --all-targets --locked` et
  `cargo build --release --locked` ont réussi sous Windows.
- Une instance hors écran a vérifié les quatre choix du menu, l'indicateur
  manuel, la couleur, le filtre et le retour au classement automatique.
- Avec un profil de test isolé, le choix manuel a été relu après un
  changement de PID. Une autre relance a confirmé le retour à l'automatique.
- Le test de stockage a vérifié la relecture des choix et la conservation
  du niveau précédent quand Windows refuse le remplacement du fichier.
- Windows a trouvé le groupe d'icônes dans `RustyPort.exe`.
  SHA-256 `89C25545F0E02689EE4BF3744173B86A0357684E33596313D5DF23DAE769D563`.

## 2026-11-24 - Redessin et sélection dense

- Les 18 tests passent en compilation de développement et en version
  optimisée. `cargo check --all-targets --locked` et la compilation de
  livraison ont réussi.
- À 500 ms avec 113 lignes sélectionnées, sur 1,8 s, les réécritures du
  détail passent de 4 à 0 et les basculements de redessin de la liste de
  8 à 0. Après 40 redimensionnements entre 900 × 630 et 1894 × 878, le
  nombre d'objets GDI reste à 39. La superposition signalée n'a pas été
  reproduite dans la fenêtre hors écran de référence.
- Ctrl+A affiche 111 ports TCP, dont 6 avec connexions et 105 à zéro.
  Le filtre des ports inactifs affiche le message d'absence de connexion.
  Le graphique figé ne reçoit aucun redessin en 1,8 s de collecte.
- Le test de charge a ouvert puis fermé 12 192 connexions TCP et reçu
  8 128 datagrammes UDP sur le bouclage en environ 70 secondes.
  L'historique à 250 ms a enregistré 256 relevés. L'export borné et
  l'échec d'export sans fichier partiel ont été vérifiés.
- Le binaire de livraison a rejeté un lot d'arrêt invalide et une
  identité périmée. Un lot valide a arrêté les deux processus de test.
- Le second lancement a retrouvé la première fenêtre. Après l'arrêt
  forcé d'une instance de test isolée, les deux fichiers temporaires
  ont disparu. Les relevés ont repris à la relance avec archivage désactivé.
- Windows a trouvé le groupe d'icônes dans `RustyPort.exe`.
  SHA-256 `3DDAFC1F4EBDFF2D8029BF7E99F01CAA755A443BDAA214011D4BBDC9563F08F1`.

## 2026-11-24 - Nouvelles connexions par port

- Les 18 tests ont réussi en développement et en version optimisée.
  Le test TCP réel remplace une connexion par une autre. Le nombre
  d'établies reste à 1 et le compteur d'arrivées détecte le remplacement.
  Le premier relevé et un port absent laissent la valeur indisponible.
- L'archive et le CSV distinguent zéro arrivée d'une mesure indisponible.
  Une charge à 250 ms avec 600 connexions TCP et 360 datagrammes UDP
  locaux a produit 80 lignes de test avec une établie et au moins une
  arrivée. La pause, les exports bornés et le nettoyage ont été vérifiés.
- À 900 × 630, la fenêtre hors écran a affiché quatre pics d'arrivées
  et une ligne stable à une connexion établie pour le même port fictif.
  Le rendu GDI des deux modes a aussi été contrôlé en mémoire.
- Windows a trouvé le groupe d'icônes dans `RustyPort.exe`.
  SHA-256 `862A0B1A6C8D5673B913B43BFFD1E7AF599E527988D35FD69E5AFD4D8EE75045`.
