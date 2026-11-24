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

## Réalisé - Menu d'actions, sélection et activité TCP

- Demander la durée au clic sur une action temporaire. Échap et Annuler
  ferment la saisie. Le retrait du blocage et l'annulation de la surveillance
  restent disponibles après activation.
- Expliquer les actions grisées et les critères de niveau. Ajouter des
  teintes discrètes et garder les couleurs système en contraste élevé.
- Si Windows refuse le droit d'arrêt, proposer l'élévation UAC et vérifier
  à nouveau le PID, l'identité du processus, le port et le statut critique.
- Trier par connexions TCP établies ou nouvelles connexions TCP observées
  dans la dernière minute.
- Sélectionner plusieurs lignes avec Ctrl+A, Ctrl+clic ou en glissant.
  Conserver la sélection pendant les relevés et le tri.
- Proposer les détails et la recherche web sur la ligne visée.
- Appliquer les actions au groupe après confirmation de ses cibles.
  Regrouper les PID identiques et les règles de pare-feu de même port et
  protocole. Indiquer le résultat des actions qui réussissent ou échouent.
- Démarrer les relevés à 500 ms. Le journal consigne la vérification du
  port VPBA dans les tables Windows.
- Figer l'affichage du graphique sur demande et afficher les connexions
  et processus observés au survol d'un échantillon. Conserver la mesure
  globale et la collecte en tâche de fond.
- Paginer l'historique sur disque et supprimer la session avec « Quitter ».
  Afficher la taille, proposer le nettoyage et suspendre les écritures sur demande.
  Garder l'archivage désactivé au lancement. Exporter en CSV toute la session
  ou une période choisie.
- Réouvrir la fenêtre de l'instance active au prochain lancement et intégrer
  l'icône aux ressources du fichier exécutable.

## Réalisé - Disposition néo-rétro

- Regrouper la cadence et la durée de surveillance dans le bandeau.
- Agrandir le graphique et ajouter des repères temporels, une légende de
  couleurs et des marqueurs au survol.
- Rapprocher les filtres du tableau et les actions du détail de la sélection.
- Replier le volet d'historique au lancement et laisser visible l'espace
  disque utilisé.
- Revenir en tête de liste après un tri explicite en conservant la
  sélection et signaler les ports dont les courbes se superposent.

## À valider

- Exécuter sur un poste Windows avec droits d'administration un blocage
  temporaire sur un port de test et vérifier son expiration.
- Vérifier l'invite UAC du nouvel arrêt sur un processus de test qui demande
  une élévation.
