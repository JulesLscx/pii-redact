# pii-redact

Pseudonymisation locale et déterministe des données personnelles, pour agents LLM.

Le modèle ne voit jamais vos vraies données ; vous, si. Les fichiers écrits sur
le disque, les commandes exécutées et la réponse affichée contiennent les vraies
valeurs — seul le trajet vers le fournisseur de LLM est pseudonymisé.

```
Vous  : « quelle est l'adresse de facturation du dernier devis ? »
        │
        ├─ l'agent lit devis.pdf         → "12 bis rue des Lilas, 69007 Lyon"
        ├─ pii-redact                    → "[ADDR_0001], [POSTAL_0001] Lyon"
        ├─ le LLM raisonne sur les jetons et répond "…est [ADDR_0001]"
        └─ pii-redact restaure           → « …est 12 bis rue des Lilas »
Vous  : lisez la vraie adresse. Le modèle ne l'a jamais reçue.
```

## Ce qui est détecté

Email · IBAN · carte bancaire · NIR (sécurité sociale) · SIRET / TVA
intracommunautaire · n° de compte ou de contrat · téléphone · immatriculation ·
adresse postale · code postal · URL contenant des identifiants · noms de
personnes ancrés par civilité (`Mme X`, `Dr X`) ou par champ (`Titulaire : X`) ·
organisations ancrées par forme juridique (`SARL X`, `mutuelle X`) · montants ·
dates.

Plus : **toute valeur déjà rencontrée une fois**. Le répertoire littéral est
persistant, donc un nom capté une seule fois par une civilité est ensuite
reconnu partout, nu, dans n'importe quel document, indéfiniment.

## Installation

### Hermes Agent

Le plugin est déjà au bon endroit (`~/.hermes/plugins/pii-redact/`). Il reste à
l'activer dans `~/.hermes/config.yaml` :

```yaml
plugins:
  enabled:
    - pii-redact
```

puis `hermes gateway restart` (ou relancer votre session). Vérification :

```bash
hermes plugins list | grep pii-redact
python3 -m piiredact doctor         # depuis ~/.hermes/plugins/pii-redact
```

### Autres hôtes (Claude Code, OpenCode, Codex, scripts)

Le cœur est un paquet Python sans aucune dépendance. Trois façons de le brancher :

**1. Bibliothèque**

```python
from piiredact import redact, restore

safe = redact(document).text     # → LLM
vrai = restore(reponse_modele)   # → utilisateur / outil
```

**2. Hooks Claude Code** — `~/.claude/settings.json` :

```json
{
  "hooks": {
    "PreToolUse":  [{"hooks": [{"type": "command", "command": "python3 -m piiredact hook"}]}],
    "PostToolUse": [{"hooks": [{"type": "command", "command": "python3 -m piiredact hook"}]}]
  }
}
```

`PostToolUse` pseudonymise les résultats d'outils (`updatedToolOutput`),
`PreToolUse` restaure les valeurs pour les outils locaux (`updatedInput`) et
refuse les outils d'egress en mode `block`.

> **Limite documentée** : `UserPromptSubmit` ne permet pas de réécrire le texte
> du prompt. La PII que vous tapez *vous-même* dans Claude Code ne peut donc pas
> être pseudonymisée en vol — vous recevez un avertissement, ou un blocage si
> `PII_REDACT_BLOCK=1`. Hermes n'a pas cette limite (le middleware `llm_request`
> couvre tout le payload).

**3. Serveur JSON-lines** — pour n'importe quel hôte capable de lancer un
sous-processus. Un processus qui reste chaud évite les ~100 ms de démarrage de
l'interpréteur à chaque événement :

```bash
python3 -m piiredact serve
{"op":"redact","text":"IBAN FR76 3000 4000 0512 3456 7890 143"}
{"ok": true, "text": "IBAN [IBAN_0001]", "counts": {"IBAN": 1}, "ms": 0.4}
```

Ops disponibles : `redact`, `restore`, `redact_args`, `restore_args`, `learn`,
`status`.

## Utilisation en ligne de commande

```bash
python3 -m piiredact redact < facture.txt      # pseudonymise
python3 -m piiredact restore < reponse.txt     # restaure
python3 -m piiredact doctor                    # config effective + invariants
python3 -m piiredact bench                     # latence mesurée
python3 -m piiredact vault count               # combien de valeurs connues
python3 -m piiredact vault list                # valeurs masquées (--reveal pour tout voir)
python3 -m piiredact vault add PERSON "Amélie" # apprendre une valeur à la main
python3 -m piiredact vault forget '[PERSON_0003]'
```

`vault add` est l'échappatoire pour ce qu'aucune règle ne peut deviner : un
prénom d'enfant, un surnom, un nom de projet. Une fois ajouté, il est masqué
partout, pour toujours.

## Configuration

Tout passe par l'environnement (dans `~/.hermes/.env` pour Hermes).

| Variable | Défaut | Effet |
|---|---|---|
| `PII_REDACT_DISABLE` | `0` | Désactive tout (no-op complet) |
| `PII_REDACT_PROFILE` | `balanced` | `balanced` ou `strict` (voir plus bas) |
| `PII_REDACT_BLOCK` | `0` | Refuse les outils d'egress porteurs de PII au lieu de les laisser passer sur jetons |
| `PII_REDACT_DB` | `$HERMES_HOME/pii-redact/mapping.db` | Emplacement du vault |
| `PII_REDACT_LANG` | `fr` | Pack(s) de règles actifs, séparés par des virgules (`fr`, `en`, ou `fr,en`) — voir `piiredact/lang/` |
| `PII_REDACT_TERMS` | — | Fichier `TYPE:valeur` chargé au démarrage |
| `PII_REDACT_NER` | `0` | Active la passe spaCy |
| `PII_REDACT_NER_MODEL` | `fr_core_news_sm` | Modèle spaCy |
| `PII_REDACT_TYPES` | — | Liste explicite de types (remplace le profil) |
| `PII_REDACT_ADD_TYPES` / `PII_REDACT_SKIP_TYPES` | — | Ajustements au profil |
| `PII_REDACT_BUDGET_MS` | `300` | Budget de latence par appel |
| `PII_REDACT_MAX_BYTES` | `4194304` | Au-delà, le contenu est tronqué (jamais transmis en clair) |
| `PII_REDACT_EGRESS_TOOLS` | — | Outils supplémentaires traités comme tiers |
| `PII_REDACT_LOCAL_TOOLS` | — | Outils forcés en « local » |
| `PII_REDACT_GUARD_PAYLOAD` | `1` | Passe finale sur le payload provider |
| `PII_REDACT_RESTORE_TOOL_ARGS` | `1` | Restauration des arguments d'outils locaux |
| `PII_REDACT_LOG_COUNTS` | `0` | Journalise les compteurs par type (jamais les valeurs) |

### Profils

**`balanced` (défaut)** — tous les identifiants directs sont pseudonymisés ; les
**montants et les dates restent lisibles**. Un montant seul, une fois le nom,
l'adresse et l'IBAN retirés, n'identifie personne — mais le masquer supprime la
capacité du modèle à additionner, comparer et raisonner sur des échéances.
C'est le profil qui préserve le plus de fonctionnalités.

**`strict`** — ajoute les montants et les dates. À choisir si votre modèle de
menace inclut la ré-identification par recoupement. Vous perdez l'arithmétique
et le raisonnement temporel du modèle.

```bash
PII_REDACT_PROFILE=strict     # tout est masqué
PII_REDACT_SKIP_TYPES=ORG,LOC # ou un réglage fin type par type
```

## Performance

Mesuré sur cette machine (`python3 -m piiredact bench`), texte très dense en PII :

| Taille | p50 | p95 |
|---|---|---|
| 4 Ko | 5 ms | 6 ms |
| 210 Ko | 167 ms | 203 ms |

Le coût est **linéaire** (~0,8 ms/Ko) et le contenu déjà vu est servi par un
cache de hash, donc la passe sur le payload provider — qui rejoue tout
l'historique avant chaque appel API — coûte quelques dizaines de microsecondes
en régime établi. Le budget de 300 ms couvre un document d'environ 300 Ko.

La passe spaCy coûte 30 à 150 ms par document : c'est pour cela qu'elle est
désactivée par défaut, et pourquoi les couches déterministes ont été conçues
pour ne pas en avoir besoin. Le **chargement** du modèle coûte lui ~16 s à
froid : il se fait donc sur un thread d'arrière-plan, déclenché au démarrage de
session. Tant qu'il n'a pas abouti, la passe NER ne renvoie rien — rappel
dégradé pendant quelques appels, jamais un appel d'outil bloqué.

## Sécurité

- Le vault SQLite est créé en `0600` dans un répertoire `0700`. Il contient les
  valeurs réelles : c'est exactement le matériel qu'on garde hors du réseau.
- **Aucun outil n'est exposé à l'agent pour lire le vault** — ce serait une
  porte d'entrée triviale vers les valeurs réelles.
- Les journaux ne contiennent jamais de valeurs, seulement des compteurs par
  type.
- Un jeton inconnu se restaure en lui-même : une base tournée dégrade en
  « marqueur inerte », jamais en sortie corrompue.

## Développement

```bash
python3 -m pytest                 # 114 tests
python3 -m piiredact doctor       # invariants (dont l'audit des motifs)
```

Le test qui compte est `tests/test_leak.py` : quatre documents français
réalistes (facture, relevé bancaire, avis d'imposition, compte rendu) et
l'assertion qu'aucune valeur déclarée ne survit. Il a trouvé deux vrais bugs à
sa première exécution.

**Piège à ne jamais réintroduire** : une règle qui se termine par `\b` casse dès
que la valeur est suivie d'une ponctuation (`1 234,56 €.`), parce qu'il n'y a
pas de frontière de mot entre `€` et `.` — et la valeur part en clair.
Utiliser `(?!\w)`. `audit_patterns()` refuse les motifs fautifs et un test le
vérifie.

Voir [SPEC.md](SPEC.md) pour les invariants, le modèle de menace et les
arbitrages.
