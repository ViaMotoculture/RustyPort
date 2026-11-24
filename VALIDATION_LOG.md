# Journal de validation OpenPort

## 2026-11-24 - État initial

- Windows, Rust 1.99.0, cible `x86_64-pc-windows-gnu`. `cargo test --locked`
  a réussi avec 3 tests sur la base importée.
- Windows a renvoyé les écoutes TCP et les sockets UDP de test en IPv4 et
  IPv6. L'arrêt du processus de test a libéré sa socket et l'identité périmée
  a été rejetée. Les scripts de pare-feu ont été analysés par PowerShell.
- L'essai du pare-feu porte sur la syntaxe. La modification de règles demande
  une recette sur un poste Windows avec droits d'administration.
