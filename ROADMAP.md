# Feuille de route OpenPort

## Réalisé - Surveillance des ports et du trafic

- Afficher « Normal », « Inconnu » ou « À risque » pour chaque port, avec le
  motif dans le détail et un filtre par niveau. Les critères décrivent des
  indices d'identité et d'exposition locale.
- Trier en cliquant sur les en-têtes, notamment par risque, port, durée et
  nombre de connexions. Afficher les risques les plus élevés en premier au départ.
- Afficher le temps écoulé depuis l'ouverture d'OpenPort, depuis la première
  observation continue du port et depuis le démarrage du processus quand
  Windows communique son heure de création.
- Afficher le nombre de connexions TCP établies associées à chaque écoute et
  les débits réellement mesurés sur les interfaces actives. Identifier les
  mesures indisponibles et la portée des données UDP.
- Préserver l'inventaire IPv4/IPv6, le filtre texte, l'actualisation manuelle
  et les actions existantes sur les processus et le pare-feu.

## Contrôles de livraison

- Sur Windows, vérifier les niveaux de risque et leurs motifs sur des cas
  connus, ainsi que l'apparition et la fermeture d'une connexion locale TCP.
- Vérifier la mesure d'un intervalle actif, calme et interrompu, puis compiler
  l'exécutable et vérifier la fenêtre, la sélection et les filtres.
- Vérifier la syntaxe des commandes de pare-feu et les protections d'arrêt
  de processus avec les tests existants.
- Consulter le journal pour l'état des contrôles Windows et de la publication.

## Réalisé - Actions et surveillance en arrière-plan

- Régler l'intervalle de relevé et afficher le détail d'un échantillon
  sous le pointeur sur le graphique.
- Reconnaître les usages attendus de services Windows confirmés pour le PID,
  même lorsque le chemin du processus est protégé.
- Donner accès aux actions depuis la ligne du processus. Prévoir l'arrêt
  seul, l'arrêt et le blocage, et l'expiration d'un blocage temporaire.
- Surveiller les relances pendant la durée saisie ou jusqu'à la fermeture
  complète. Permettre l'annulation depuis « Relances ».
- Masquer la fenêtre avec la croix et proposer « Ouvrir » et « Quitter »
  depuis l'icône OpenPort dans la zone de notification.

## À valider

- Exécuter sur un poste Windows avec droits d'administration un blocage
  temporaire sur un port de test et vérifier son expiration.
- Publier les commits de RustyPort sur la branche `main` du dépôt
  de référence. Le journal indique l'état de l'accès Git.
