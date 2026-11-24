# Feuille de route OpenPort

## Chantier - Surveillance des ports et du trafic

- Afficher « Normal », « Inconnu » ou « À risque » pour chaque port, avec le
  motif dans le détail et un filtre par niveau. Les critères décrivent des
  indices d'identité et d'exposition locale.
- Afficher le temps écoulé depuis l'ouverture d'OpenPort, depuis la première
  observation continue du port et depuis le démarrage du processus quand
  Windows communique son heure de création.
- Afficher le nombre de connexions TCP établies associées à chaque écoute et
  les débits réellement mesurés sur les interfaces actives. Identifier les
  mesures indisponibles et la portée des données UDP.
- Préserver l'inventaire IPv4/IPv6, le filtre texte, l'actualisation manuelle
  et les actions existantes sur les processus et le pare-feu.

## Contrôles prévus

- Sur Windows, vérifier les niveaux de risque et leurs motifs sur des cas
  connus, ainsi que l'apparition et la fermeture d'une connexion locale TCP.
- Vérifier la mesure d'un intervalle actif, calme et interrompu, puis compiler
  l'exécutable et vérifier la fenêtre, la sélection et les filtres.
- Vérifier la syntaxe des commandes de pare-feu et les protections d'arrêt
  de processus avec les tests existants.
