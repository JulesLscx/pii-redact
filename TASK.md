# Mission — Plugin Hermes « pii-redact » : pseudonymisation PII avant envoi LLM

Tu es dans une session Claude Code distante orchestrée par Hermes pour JULES.
Jules a une contrainte de confidentialité absolue : **aucune PII réelle ne doit
jamais fuiter vers un LLM** (voir son profil). Ce plugin Hermes doit rendre ça
systématique au niveau de l'agent.

## Objectif
Construire un plugin Hermes (`~/.hermes/plugins/pii-redact/`) qui
pseudonymise les PII dans le trafic vers le LLM et les dé-pseudonymise en
retour, en réutilisant l'approche ÉPROUVÉE du pipeline graphrag déjà déployé
sur cette machine (référence de code ci-dessous).

## Architecture cible (calquée sur graphrag-personnel, déjà validé)
1. **Détection locale** : NER spaCy `fr_core_news_sm` + règles regex FR (PERSON,
   ORG, LOC, adresses, IBAN, SIRET, NIR, cartes, téléphones, emails, montants,
   dates, codes postaux).
2. **Mapping déterministe persistant** (SQLite) : même valeur réelle → même
   jeton `[TYPE_NNNN]`, dédupliqué par hash SHA-256 de la valeur normalisée.
3. **Le LLM ne reçoit QUE les jetons** ; le mapping réel→jeton reste local.
4. **Dé-pseudonymisation locale** de la réponse (regex inverse → lookup SQLite)
   avant affichage.
5. Tests : (a) aucune PII réelle dans le texte pseudo, (b) déterministe,
   (c) l'inverse restaure les valeurs.

## COMMENT faire (à suivre impérativement)
1. **Lis d'abord l'API réelle des plugins Hermes** dans le code source installé :
   `/usr/local/lib/hermes-agent/` — en particulier le système de hooks plugins.
   Découvre quels hooks existent (ex. `pre_tool_call`, `transform_tool_result`,
   et cherche s'il existe des hooks de niveau prompt/LLM comme
   `transform_user_prompt` / `pre_llm_call` / `transform_llm_response`…). NE
   DEVIENNE PAS à partir du seul exemple `security-guidance` : vérifie la liste
   complète des hooks supportés dans le source avant de choisir.
   Regarde aussi `/usr/local/lib/hermes-agent/plugins/plugin_utils.py`
   (`lazy_singleton`, `SingletonSlot` — thread-safe, à utiliser pour le client
   SQLite/spaCy car les sessions Hermes sont multithreadées).
2. **Exemple canonique à imiter** : `/usr/local/lib/hermes-agent/plugins/security-guidance/`
   (structure `plugin.yaml` + `__init__.py` avec `register(ctx)`).
3. **Référence d'implémentation PII** (le pipeline graphrag déjà déployé) :
   - `/root/graph-rag/src/graphrag/pseudonymizer.py` — LE fichier clé : NER +
     regex + mapping SQLite + dé-pseudonymisation.
   - `/root/graph-rag/src/graphrag/config.py` — bornes/limites.
   - `/root/graph-rag/src/graphrag/db.py` — schéma SQLite du mapping.
   - Support conceptuel : `~/.hermes/skills/note-taking/pii-pseudonymization/SKILL.md`
     et son `references/graphrag-pipeline-deploy.md`.
   Réutilise le plus possible de ce code (adapté en plugin Hermes), ne le réécris
   pas de zéro.
4. **Piège CRITIQUE connu** (déjà réglé dans graphrag) : toute règle regex PII
   terminant par `\b` casse quand la PII est suivie de ponctuation (`.` `,` `;`
   `)` `€` …) → la valeur fuit vers le LLM. Utiliser le lookahead négatif
   `(?!\w)` à la place, et couvrir les cas ponctués par un test de régression
   (voir `test_amounts_with_trailing_punctuation_are_pseudonymized` dans graphrag).
5. Priorité des règles : les plus spécifiques d'abord (IBAN, NIR, SIRET, CARD),
   puis les génériques (code postal 5 chiffres) ; marquer les zones déjà
   capturées pour éviter les chevauchements.

## Livrables
- `plugin.yaml` (name: pii-redact, version, description, hooks utilisés)
- `__init__.py` avec `register(ctx)` branchant les hooks retenus
- module(s) de détection/pseudonymisation (réutiliser le pattern graphrag)
- module SQLite de mapping + dé-pseudonymisation
- `README.md` + un `SPEC.md` court
- tests pytest (`tests/`) incluant LE test de fuite : un corpus de fixtures PII
  FR réalistes (facture, relevé, avis d'imposition, note de cours) et assertion
  « aucune vraie valeur PII n'apparaît dans le texte pseudonymisé »
- config : permettre un mode **dès défaut** (non-bloquant vs bloquant) via
  variable d'env, façon `security-guidance` (`PII_REDACT_DISABLE`,
  `PII_REDACT_BLOCK`, `PII_REDACT_DB`).

## Contraintes
- Python : la machine a 3.11 (système) ; le venv Hermes est sous
  `/usr/local/lib/hermes-agent/venv/`. Attention : spaCy `fr_core_news_sm` est
  déjà installé dans le venv du projet graphrag (`/root/graph-rag/.venv/`), pas
  forcément dans celui d'Hermes. Pour deps lourdes (spaCy, torch,
  sentence-transformers), privilégier l'import **optionnel/lazy** : le plugin
  doit marcher avec un fallback 100% regex si spaCy est absent, et noter dans le
  README comment installer le modèle si on veut le NER complet.
- Ne JAMAIS hardcoder `~/.hermes` : utiliser `ctx` (le contexte plugin) pour
  l'emplacement des données (fichier SQLite du mapping) ou `get_hermes_home()`.
- Secrets : ne rien mettre dans le mapping ; le mapping SQLite n'est qu'une
  table valeur-hash→jeton, il reste local à la machine.
- Ne pas casser le prompt caching Hermes ni l'alternance des rôles.
- Code propre, type hints, docstrings.

## Base de données / état
Stocke le SQLite du mapping sous le home Hermes (ex. `<home>/pii-redact/mapping.db`),
créé à la demande. Initialise-le depuis le code graphrag comme modèle, mais ne
dépend pas de l'installation graphrag (plugin autonome).

## Vérification avant de terminer
- `uv run pytest` (ou pytest du venv Hermes) vert sur les tests du plugin.
- Un test manuel : pipeline sur un texte FR réaliste avec vraies PII →
  texte pseudonymisé sans fuite, puis dé-pseudonymisé = texte d'origine.
- Résume ce que tu as fait et ce qui reste (déploiement des hooks actifs).
