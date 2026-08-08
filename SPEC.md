# SPEC — pii-redact

## Objectif

Aucune donnée personnelle réelle ne quitte la machine vers un LLM, **sans perdre
une seule fonctionnalité de l'agent**. L'utilisateur doit pouvoir continuer à
demander « quelle est l'adresse de facturation ? », « combien j'ai payé ? »,
« envoie un mail au client » — et obtenir une vraie réponse d'un modèle qui n'a
jamais vu la vraie valeur.

## Invariants

| # | Invariant | Vérifié par |
|---|---|---|
| I1 | Aucune valeur PII réelle d'un document de test n'apparaît dans le texte transmis | `test_leak.py::test_no_real_value_survives_redaction` |
| I2 | `restore(redact(x)) == x` | `test_roundtrip_restores_the_original` |
| I3 | `redact(redact(x)) == redact(x)` (idempotence) | `test_redaction_is_idempotent` |
| I4 | Même valeur réelle → même jeton, dans le run et entre processus | `test_same_value_yields_same_token_across_processes` |
| I5 | Aucune règle ne se termine par `\b` | `audit_patterns()` + `test_no_rule_pattern_ends_with_word_boundary` |
| I6 | Les identifiants de corrélation (`tool_call_id`…) et les schémas d'outils ne sont jamais réécrits | `test_provider_payload_is_redacted_without_touching_ids` |
| I7 | Coût < 300 ms par appel d'outil sur un document réaliste | `test_latency.py` |
| I8 | Un outil d'egress (recherche web, fetch, navigateur) ne reçoit jamais de valeur réelle | `test_egress_tool_keeps_tokens` |
| I9 | Le mapping SQLite est en `0600` | `test_vault_file_is_owner_only` |
| I10 | Sortie identique à l'octet près pour un historique identique (cache de prompt préservé) | `test_payload_pass_is_deterministic_across_calls` |

## Architecture

```
                 machine locale                     │      réseau
                                                    │
  fichiers ──► outil ──► [résultat brut] ───────────┼──► ✗ jamais
                              │                     │
                              ▼ redact()            │
                        [TYPE_NNNN] ────────────────┼──► LLM
                              ▲                     │      │
                              │ restore()           │      │ réponse
  disque ◄── outil local ◄────┤                     │      │ (jetons)
  écran  ◄── utilisateur ◄────┴─────────────────────┼──────┘
                                                    │
  vault SQLite (jeton → valeur réelle) ── local, 0600, jamais transmis
```

### Couches de détection (ordre d'exécution)

1. **Pré-réservation des jetons** — les zones contenant déjà `[TYPE_NNNN]` sont
   gelées. C'est ce qui rend l'opération idempotente et donc sûre à appliquer à
   plusieurs étages de la même requête.
2. **Règles déterministes** (`rules.py` + `lang/`) — le moteur (`rules.py`)
   est neutre ; les règles elles-mêmes vivent dans un pack par langue
   (`lang/fr.py`, `lang/en.py`) plus un pack commun aux formes universelles
   (`lang/common.py` : email, IBAN, carte, IP). Le pack FR couvre NIR,
   SIRET/TVA, n° de compte contextuel, téléphone, immatriculation, adresse
   postale, noms ancrés par civilité (`Mme X`) ou par champ (`Titulaire : X`),
   organisations ancrées par forme juridique, montants, dates, code postal.
   `PII_REDACT_LANG` sélectionne le ou les packs actifs (défaut : `fr`) ; les
   règles composées sont triées par priorité pour que "spécifique avant
   générique" tienne aussi entre langues.
3. **Répertoire littéral** (`matcher.py`) — toute valeur déjà connue du vault,
   plus les termes fournis par l'utilisateur. Une valeur détectée une fois est
   re-détectée partout ensuite, sans ancre.
4. **Balayage intra-document** — les valeurs découvertes pendant *cette* passe
   sont recherchées à nouveau dans le même texte (une première mention ancrée
   couvre les mentions nues qui suivent).
5. **NER spaCy** (`ner.py`) — optionnel, désactivé par défaut, borné par le
   budget de latence.

Les couches 1–4 sont **100 % déterministes**. La couche 5 n'est jamais un
prérequis : sans spaCy, le pipeline est complet et correct, juste avec un
rappel moindre sur les noms nus jamais vus.

### Attribution des jetons

`SHA-256(type + ":" + valeur normalisée)` → ligne unique dans `pii_mapping` →
`[TYPE_NNNN]` (séquence par type, ≥ 4 chiffres). La normalisation replie la
casse, les accents et les séparateurs selon le type, pour que `+33 6 12 34 56 78`
et `06 12 34 56 78` ne consomment pas deux jetons.

## Modèle de menace

**Couvert** — fuite de PII vers le fournisseur de LLM, quel que soit le chemin
d'entrée dans le contexte (lecture de fichier, sortie de commande, mémoire
injectée, message collé) ; fuite vers un service tiers via un outil d'egress.

**Non couvert** — un adversaire ayant déjà un accès local (le vault contient les
valeurs en clair, protégé par les permissions du système de fichiers) ; la
ré-identification par recoupement de quasi-identifiants laissés en clair en
profil `balanced` (montants, dates) ; les documents que l'agent n'ouvre jamais.

## Décisions et arbitrages

**Profil `balanced` par défaut.** Les identifiants directs (nom, email, IBAN,
adresse, téléphone…) sont toujours pseudonymisés. Les montants et les dates ne
le sont qu'en profil `strict`. Raison : un montant seul, une fois tous les
identifiants retirés, n'identifie personne — mais le masquer supprime la
capacité du modèle à additionner, comparer, raisonner sur un échéancier. Le
profil `strict` reste à une variable d'environnement de distance pour qui
accepte cet arbitrage.

**Aucun outil exposé à l'agent pour lire le vault.** Ce serait une porte
d'entrée triviale vers les valeurs réelles : le modèle demanderait simplement le
contenu de la table. L'inspection passe par la CLI, côté humain.

**Restauration limitée aux outils locaux.** Rendre les valeurs réelles à un
outil de recherche web échangerait une fuite vers le LLM contre une fuite vers
un tiers — ce n'est pas un progrès.

**Sur-détection assumée.** Une adresse capturée deux mots trop loin est sans
conséquence (la restauration est exacte, l'invariant I2 le vérifie). Une
sous-détection est une fuite. Toutes les règles penchent du côté sûr.

## Limites connues

- Un nom propre nu, jamais vu, sans civilité ni champ, n'est pas détecté par les
  couches déterministes (`test_known_limitations_are_explicit` le fige). Trois
  remèdes : `PII_REDACT_NER=1`, un fichier de termes, ou une première mention
  ancrée dans n'importe quel document.
- Sous Claude Code, `UserPromptSubmit` ne permet pas de réécrire le prompt : la
  PII tapée directement par l'utilisateur ne peut pas être pseudonymisée en vol
  (avertissement, ou blocage en mode `block`). Hermes n'a pas cette limite.
- Le coût est linéaire en taille : ~0,8 ms/Ko sur du texte très dense en PII.
  Le budget de 300 ms couvre donc ~300 Ko par appel ; au-delà, la
  pseudonymisation continue (on ne troque jamais la confidentialité contre la
  latence) et `PII_REDACT_MAX_BYTES` borne le pire cas en tronquant, avec une
  note explicite à destination du modèle.
