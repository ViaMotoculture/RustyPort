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

Le graphique couvre les 60 dernières secondes. « Ports sélectionnés » ouvre la vue **Connexions établies** par défaut. Le menu voisin permet de choisir la mesure.

- **Débit des interfaces** affiche les octets reçus et envoyés par seconde, cumulés sur les interfaces actives hors bouclage.
- **Débit par port** affiche une courbe en octets par seconde par port TCP ou UDP sélectionné. La courbe additionne les octets reçus et envoyés rapportés par Windows. Le survol détaille les deux sens. La collecte utilise des fenêtres d’au moins une seconde et demande les droits de capture de Windows.
- **Nouvelles connexions** affiche un pic pour chaque relevé où de nouvelles connexions TCP ont été observées. Une connexion ouverte et refermée entre deux relevés peut manquer.
- **Connexions établies** affiche le nombre de connexions TCP ouvertes à chaque relevé. Une ligne plate indique que ce nombre est stable.

La légende indique la valeur du dernier relevé. Survolez un port dans la légende pour afficher son détail, ou survolez le tracé pour lire un relevé plus ancien. Les couleurs des ports déjà sélectionnés restent stables quand de nouvelles courbes apparaissent. Pour une sélection dense, la légende met en avant les ports dont la mesure est non nulle. Les ports restés à zéro partagent un tracé et les ports sans relevé sont comptés séparément.

« Pause » fige le graphique pendant que les relevés continuent. L’archivage local est désactivé au démarrage. Le volet « Historique » permet de l’activer, de parcourir les relevés archivés, de voir l’espace utilisé et de nettoyer la session. Les exports CSV portent sur toute la session ou une période choisie. La colonne `tcp_nouvelles_releve` est vide quand la comparaison entre deux relevés est indisponible. Les débits par port et leur durée de mesure figurent sur les lignes TCP et UDP lorsqu’ils ont été mesurés. Les fichiers temporaires sont supprimés lorsque RustyPort quitte. Les CSV restent à l’emplacement choisi.

## Agir sur un port ou un processus

Le menu d’actions permet de terminer les processus autorisés, de bloquer le trafic entrant d’un port dans le Pare-feu Windows et de retirer un blocage. Pour un blocage temporaire, RustyPort demande la durée. La surveillance des relances peut arrêter de nouveau une application sélectionnée pendant la durée choisie ou jusqu’à la fermeture complète de RustyPort. Le bouton « Relances » permet d’annuler cette surveillance.

Le binaire de livraison `RustyPort.exe` demande l’autorisation administrateur Windows dès le lancement. Ces droits permettent de mesurer le débit par port et d’utiliser les actions système autorisées, notamment celles du pare-feu.

## Compiler et lancer

Depuis un terminal PowerShell sous Windows, avec Rust et Cargo installés, exécutez ces commandes à la racine du projet.

```powershell
cargo test --locked
cargo build --release --locked
.\target\release\rustyport.exe
```

Pour préparer le binaire de livraison avec l’icône et la demande d’autorisation Windows, exécutez ces commandes après compilation.

```powershell
Copy-Item .\target\release\rustyport.exe .\RustyPort.exe
Start-Process .\target\release\rustyport.exe -ArgumentList '--embed-icon', '.\RustyPort.exe' -WorkingDirectory (Get-Location).Path -WindowStyle Hidden -Wait
.\RustyPort.exe
```

La croix masque la fenêtre et laisse RustyPort surveiller les ports dans la zone de notification. Un nouveau lancement rouvre l’instance active. « Quitter RustyPort », dans le menu de l’icône de notification, ferme le processus. Si le nettoyage se bloque, RustyPort force son propre arrêt après 1,5 seconde. Si un export CSV est en cours, la fermeture démarre automatiquement à la fin de l’export.
