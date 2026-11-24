# RustyPort

RustyPort est un utilitaire Windows écrit en Rust avec une interface Win32. Il affiche les ports TCP en écoute, les sockets UDP et les processus qui les utilisent.

## Surveiller les ports

- La liste indique l’adresse locale, le protocole, le PID et la durée d’observation de chaque port. Le détail de la ligne affiche aussi l’âge du processus lorsqu’il est disponible.
- La cadence se règle de 250 ms à 10 s dans le bandeau, avec 500 ms par défaut. Filtrez la liste par texte ou par niveau. Cliquez sur « TCP établies » pour trier par connexions en cours ou sur « Nouv. TCP / 60 s » pour trier par activité récente.
- Les niveaux « Normal », « Inconnu » et « À risque » s’appuient sur l’adresse d’écoute, l’usage habituel du port et l’identification du processus. Le bouton « Critères de niveau » explique ces repères. Le pare-feu et la configuration réseau déterminent l’accessibilité effective d’un port.
- Le menu **Niveau** du clic droit permet de choisir un niveau ou de rétablir le classement automatique. Un astérisque signale un choix manuel, conservé d’un lancement à l’autre sur le compte Windows.
- Sélectionnez plusieurs lignes avec Ctrl+A, Ctrl+clic ou un glisser. Le menu contextuel donne accès aux détails, à la recherche web et aux actions sur la sélection. Les actions groupées demandent une confirmation.

« Rechercher sur le web » ouvre Google dans le navigateur avec le nom du processus, le numéro de port et le protocole. La recherche se déclenche depuis le menu.

## Lire le graphique et conserver un relevé

Le graphique global cumule les débits reçus et envoyés sur les interfaces réseau actives hors bouclage. Le survol affiche les débits du relevé ainsi que les connexions observées sur un port TCP au même moment, lorsqu’elles existent. Avec « Ports TCP sélectionnés », chaque courbe indique le nombre de connexions TCP établies pour un port. Le tableau indique aussi les sockets UDP présentes. Les compteurs d’activité par port portent sur les connexions TCP.

La légende affiche en premier les ports qui ont eu des connexions sur la période affichée. Les ports restés à zéro partagent un tracé et les ports sans relevé sont comptés séparément.

« Pause » fige le graphique pendant que les relevés continuent. L’archivage local est désactivé au démarrage. Le volet « Historique » permet de l’activer, de parcourir les relevés archivés, de voir l’espace utilisé et de nettoyer la session. Vous pouvez exporter les relevés archivés en CSV pour toute la session ou pour une période choisie. Les fichiers temporaires sont supprimés lorsque RustyPort quitte. Les CSV restent à l’emplacement choisi.

## Agir sur un port ou un processus

Le menu d’actions permet de terminer les processus autorisés, de bloquer le trafic entrant d’un port dans le Pare-feu Windows et de retirer un blocage. Pour un blocage temporaire, RustyPort demande la durée. La surveillance des relances peut arrêter de nouveau une application sélectionnée pendant la durée choisie ou jusqu’à la fermeture complète de RustyPort. Le bouton « Relances » permet d’annuler cette surveillance.

Les relevés fonctionnent sans élévation. Les modifications du pare-feu et certains arrêts de processus demandent une autorisation d’administrateur via Windows.

## Compiler et lancer

Depuis un terminal PowerShell sous Windows, avec Rust et Cargo installés, exécutez ces commandes à la racine du projet.

```powershell
cargo test --locked
cargo build --release --locked
.\target\release\rustyport.exe
```

Pour créer une copie dont l’icône apparaît dans l’Explorateur Windows, exécutez ces commandes après compilation.

```powershell
Copy-Item .\target\release\rustyport.exe .\RustyPort.exe
Start-Process .\target\release\rustyport.exe -ArgumentList '--embed-icon', '.\RustyPort.exe' -WorkingDirectory (Get-Location).Path -WindowStyle Hidden -Wait
.\RustyPort.exe
```

La croix masque la fenêtre et laisse RustyPort surveiller les ports dans la zone de notification. Un nouveau lancement rouvre l’instance active. Pour arrêter la surveillance, choisissez « Quitter RustyPort » depuis l’icône de notification.
