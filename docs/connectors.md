# Ajouter un connecteur

Ce document explique comment brancher pii-redact sur un hôte qui n'est pas
encore supporté. Il s'adresse à quelqu'un qui écrit le quatrième adapter, pas à
quelqu'un qui modifie le moteur — et c'est précisément la séparation que le
plugin défend : **aucun connecteur ne contient de logique de détection**.

## 1. Le contrat minimal

Le cœur n'expose que deux appels, et c'est délibérément tout ce qu'il expose :

```python
from piiredact import redact, restore

resultat = redact(texte)   # -> RedactionResult : .text, .counts(), .truncated, .elapsed_ms
vrai     = restore(texte)  # -> str
```

Écrire un connecteur, c'est donc répondre à deux questions, et rien d'autre :

| Question | Réponse attendue |
|---|---|
| **Où le texte sort-il de la machine ?** | Ce flux passe par `redact()` avant de partir. |
| **Où le texte revient-il vers l'utilisateur ou vers un outil local ?** | Ce flux passe par `restore()` avant d'être rendu. |

Tout le reste — le vault SQLite, les règles compilées, le répertoire littéral,
le cache de hash — vit derrière `get_redactor()`, qui construit un singleton par
processus. Un connecteur ne l'instancie jamais lui-même : il appelle
`piiredact.redact` / `piiredact.restore`, ou `get_redactor()` s'il a besoin des
méthodes plus fines (`redact_obj`, `redact_payload`, `restore_obj`, `learn`).

> **Conséquence pratique** : gardez le processus chaud. Un `python -m piiredact
> redact` par événement paie ~100 ms de démarrage d'interpréteur ; le même appel
> dans un processus déjà chaud coûte ~1 ms. C'est le seul choix d'architecture
> qui change vraiment les chiffres.

## 2. Quel type de connecteur écrire

```
L'hôte peut-il charger du Python dans son propre processus ?
├── oui, et il expose des hooks / callbacks
│     → adapter dédié, calqué sur piiredact/adapters/hermes.py
│       (le plus intégré : quatre coutures, latence minimale)
│
└── non
    ├── il peut lancer un sous-processus
    │     → réutilisez piiredact/adapters/stdio.py tel quel
    │       (`python3 -m piiredact serve`, JSON ligné sur stdin/stdout)
    │       Rien à écrire côté plugin : seulement le client, côté hôte.
    │
    └── il ne parle que HTTP
          → variante serveur (voir §5)
```

Et, orthogonalement au sens entrant/sortant :

```
Vous ne voulez pas intercepter le flux, seulement l'observer ?
      → connecteur sortant, calqué sur piiredact/adapters/telemetry.py
```

### Les adapters existants comme modèles

| Module | Protocole hôte | À imiter quand… |
|---|---|---|
| `piiredact/adapters/hermes.py` | hooks + middleware in-process | l'hôte vous donne des callbacks Python |
| `piiredact/adapters/stdio.py` | JSON ligné sur stdin/stdout | l'hôte sait lancer un sous-processus |
| `piiredact/adapters/claude_code.py` | événements JSON de hooks (un par exécution) | l'hôte impose un processus par événement |
| `piiredact/adapters/telemetry.py` | aucun — consomme les résultats | vous voulez mesurer, agréger ou exporter |

## 3. Les trois cas d'usage

### (a) Redaction seule du contenu sortant

Le cas le plus simple et le plus fréquent : l'hôte envoie du texte quelque part,
vous voulez qu'il parte pseudonymisé. Une seule couture.

```python
from piiredact import redact

def on_outbound(text: str) -> str:
    return redact(text).text
```

Points d'attention :

- si le contenu est du JSON, utilisez `get_redactor().redact_payload(payload)` :
  il tente d'abord le chemin structuré, donc un remplacement ne peut pas
  chevaucher un guillemet et casser l'enveloppe que l'hôte s'apprête à parser ;
- si vous manipulez un payload de fournisseur LLM complet (messages, outils,
  identifiants de corrélation), n'écrivez pas votre propre parcours : appelez
  `piiredact.payloads.redact_request()`, qui sait déjà ce qu'il ne faut **pas**
  toucher (`tool_call_id`, schémas d'outils, champs de contrôle).

### (b) Redaction + restauration (boucle fermée)

C'est le cas qui préserve les fonctionnalités : le modèle raisonne sur des
jetons, l'utilisateur lit des vraies valeurs.

```python
from piiredact import redact, restore

def ask(model, question: str, document: str) -> str:
    reponse = model(redact(document).text, redact(question).text)
    return restore(reponse)          # jamais optionnel — voir §4
```

Deux garde-fous du cœur rendent cette boucle sûre :

- **idempotence** — `redact(redact(x)) == redact(x)`. Les zones contenant déjà
  `[TYPE_NNNN]` sont gelées avant toute règle. Vous pouvez donc appliquer la
  pseudonymisation à plusieurs étages du même trajet sans double-jetonnage.
- **jeton inconnu → lui-même** — `restore()` laisse intact un jeton absent du
  vault. Une base tournée dégrade en « marqueur inerte », jamais en sortie
  corrompue.

### (c) Restauration des arguments d'un outil local

Le modèle produit `{"path": "/tmp/devis.txt", "content": "à [EMAIL_0001]"}` ; le
fichier doit contenir la vraie adresse. Mais si l'outil est une recherche web,
restaurer échangerait une fuite vers le LLM contre une fuite vers un tiers.

Ne réimplémentez pas cet arbitrage : il est déjà dans `piiredact/policy.py`.

```python
from piiredact import get_redactor
from piiredact.payloads import restore_args
from piiredact.policy import should_restore_args

def on_tool_call(tool_name: str, args: dict) -> dict:
    red = get_redactor()
    settings = red.settings
    if not should_restore_args(tool_name, settings.egress_extra, settings.local_extra):
        return args                      # outil d'egress : il tourne sur jetons
    new_args, changed = restore_args(red, args)
    return new_args if changed else args
```

`should_restore_args()` reconnaît les noms quel que soit le style
(`web_search`, `WebSearch`, `web.search`, `browser.navigate`), et
`restore_args()` saute les clés de corrélation (`PROTECTED_ARG_KEYS`) — sans
quoi un identifiant d'appel à cinq chiffres finirait réécrit comme un code
postal et la comptabilité d'outils de l'hôte se casserait silencieusement.

## 4. Les pièges

**Ne jamais laisser tomber la restauration sur un chemin critique.**
La pseudonymisation peut échouer « en sécurité » : on abandonne le résultat, ou
on bloque. La restauration, non — c'est ce que l'utilisateur lit et ce que
l'outil local écrit sur disque. Faites la restauration **d'abord**, puis la
journalisation, la télémétrie, le reste ; jamais l'inverse. Le connecteur de
télémétrie applique exactement cette règle
(`TelemetryConnector.restore` restaure avant d'émettre, et le test
`test_a_broken_sink_never_costs_a_restoration` la fige).

**Fail-safe asymétrique.** Les deux directions n'ont pas le même mode de panne
souhaitable :

| Direction | En cas d'erreur inattendue |
|---|---|
| sortante (`redact`) | ne **jamais** laisser passer le texte brut : abandonner le résultat (mode non-bloquant) ou refuser l'opération (mode bloc) |
| entrante (`restore`) | laisser le jeton en place : c'est inerte, jamais dangereux |

**Mode bloc vs non-bloc (`PII_REDACT_BLOCK`).** Par défaut (`0`), un outil
d'egress porteur de PII s'exécute sur les jetons : non destructif, l'agent
continue d'avancer. En mode bloc (`1`), l'appel est refusé avec un message que
le modèle peut exploiter. Un connecteur doit lire `settings.block` et non
inventer sa propre politique :

```python
settings = get_redactor().settings
if settings.block:
    return {"action": "block", "message": "…"}
```

**Ne pas casser le prompt caching.** Le fournisseur ne recalcule pas un préfixe
identique — mais « identique » veut dire *identique à l'octet près*.
L'attribution des jetons est adressée par contenu
(`SHA-256(type + ":" + valeur normalisée)`), donc un même historique produit les
mêmes octets à chaque appel. Un connecteur casse cette propriété s'il ajoute
quelque chose de variable dans le texte envoyé : horodatage, compteur, numéro de
requête, ordre de dictionnaire non stable. Gardez ce genre de métadonnée dans un
canal latéral (c'est exactement le rôle de `telemetry.py`), pas dans le payload.
L'invariant I10 (`test_payload_pass_is_deterministic_across_calls`) le vérifie
côté Hermes ; refaites le même test dans votre connecteur.

**Les priorités de règles sont déjà gérées.** N'ajoutez pas de pré-filtrage,
d'ordre de passage ou de « d'abord l'IBAN puis le code postal » dans un
connecteur. Les règles portent une `priority` et le pack composé est trié, y
compris entre langues ; les chevauchements sont arbitrés par
`resolve_overlaps()`. Toute logique de détection dans un adapter est un bug en
attente : elle ne bénéficiera d'aucune correction du cœur et divergera des
autres hôtes.

**Ne jamais journaliser de valeurs.** Compteurs par type, tailles, durées — rien
d'autre. `RedactionResult.counts()` est fait pour ça, et
`piiredact.adapters.telemetry.is_safe_record()` transforme cette règle en
assertion exécutable.

**Un connecteur ne doit pas exposer le vault à l'agent.** Pas d'outil « lire le
mapping » : le modèle demanderait simplement le contenu de la table.
L'inspection passe par la CLI, côté humain.

## 5. Variante serveur HTTP

Pour un hôte qui ne sait que parler HTTP, le plus court chemin est d'envelopper
`piiredact.adapters.stdio.handle_request()` — la logique d'opérations est déjà
là, seul le transport change :

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

from piiredact.adapters.stdio import handle_request

class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        response = handle_request(json.loads(body))
        payload = json.dumps(response, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

HTTPServer(("127.0.0.1", 8787), Handler).serve_forever()   # loopback uniquement
```

**Écoutez sur `127.0.0.1`, jamais sur `0.0.0.0`.** Ce serveur restaure des
valeurs réelles à qui les demande : exposé sur le réseau, c'est le vault en
libre-service. Si vous devez sortir de la machine, mettez une authentification
et traitez l'ensemble comme le vault lui-même (SPEC.md, modèle de menace).

## 6. Le connecteur de référence : télémétrie

`piiredact/adapters/telemetry.py` est l'exemple fourni pour la direction
**sortante / observabilité**. Il n'intercepte rien : il appelle le cœur comme
n'importe quel appelant, renvoie ses résultats inchangés, et émet un
enregistrement de compteurs par appel.

### Ce qu'il émet

Un enregistrement ne contient que les champs de `EVENT_FIELDS` :

```json
{"at": "2026-08-08T14:31:07.482+00:00", "op": "redact", "source": "facture",
 "spans": 13, "counts": {"EMAIL": 2, "IBAN": 1, "PERSON": 3},
 "chars_in": 612, "chars_out": 588, "elapsed_ms": 4.9,
 "truncated": false, "cached": false}
```

Il n'y a **aucun champ capable de porter du texte de document** — ni le texte
d'origine, ni le texte pseudonymisé, ni les spans, ni les jetons. C'est une
propriété de structure, pas une discipline de relecture :
`is_safe_record()` la vérifie, et `tests/test_telemetry.py` rejoue tout le
corpus de fuite à travers le connecteur pour s'assurer qu'aucune valeur réelle
n'atteint un sink. Un collecteur est un endpoint réseau comme un autre.

### Les sinks

| Sink | Usage |
|---|---|
| `JsonLinesSink(stream)` | un objet JSON par ligne — log shipper (Vector, Fluent Bit, Loki) ou simple `tail -f` |
| `MemorySink()` | agrégation en mémoire, tests, « on expédie une fois en fin de session » |
| `HttpSink(url, batch_size=…, transport=…)` | `POST` par lots vers un collecteur |

Ajouter un sink, c'est trois méthodes : `emit(record)`, `flush()`, `close()`.

### Exemple

```python
import sys
from piiredact.adapters.telemetry import JsonLinesSink, TelemetryConnector

with TelemetryConnector([JsonLinesSink(sys.stderr)], source="ingest") as probe:
    for chemin in chemins:
        texte = chemin.read_text(encoding="utf-8")
        envoyer_au_modele(probe.redact(texte, source=chemin.name).text)
    print(probe.summary())
    # {'calls': 42, 'spans': 517, 'counts': {'EMAIL': 61, 'IBAN': 12, ...},
    #  'restored': 0, 'truncated': 0, 'cached': 7, 'dropped': 0,
    #  'total_ms': 212.4, 'p50_ms': 4.8, 'p95_ms': 11.2}
```

`spans` et `counts` ne comptent que la direction sortante ; les jetons résolus
au retour sont reportés séparément dans `restored`. Additionner les deux
donnerait un nombre qui ne veut rien dire : une valeur masquée puis restaurée
est une valeur protégée, pas deux.

Si l'hôte appelle déjà le cœur lui-même (un hook Hermes, le serveur stdio), ne
passez pas par les enveloppes : donnez le résultat déjà calculé.

```python
# dans piiredact/adapters/hermes.py, on_transform_tool_result
result = red.redact(payload)
probe.observe(result, source=f"hermes:{tool_name}")
```

### Brancher un vrai collecteur

Les tests utilisent soit un `transport` injecté, soit un serveur HTTP jetable
sur `127.0.0.1` : **aucune écriture réseau réelle**. Pour la production :

```python
from piiredact.adapters.telemetry import HttpSink, TelemetryConnector

sink = HttpSink(
    "https://collector.interne/v1/pii-redact",
    batch_size=50,          # une requête par 50 événements, pas par redaction
    timeout=2.0,
    headers={"Authorization": "Bearer …"},
)
probe = TelemetryConnector([sink], source="hermes-gateway")
```

Le corps posté est `{"records": [ … ]}`. `transport` accepte
`(url, body, headers, timeout)` : passez-y le client HTTP maison de votre
infrastructure (retries, mTLS, auth) plutôt que `urllib` si vous en avez un.

Un lot qui échoue est **abandonné, jamais rejoué** : conserver un tampon
croissant et retenter sur un collecteur en panne coûterait de la mémoire et de
la latence à chaque appel suivant. Les compteurs sont peu chers à perdre,
l'agent non. `HttpSink.failed` et `TelemetryConnector.dropped` rendent la perte
visible.

## 7. Checklist avant de considérer un connecteur terminé

- [ ] Le flux sortant passe par `redact()` — **tous** les chemins, pas seulement
      le principal (un payload de fournisseur est le seul endroit où tout
      converge : voir `payloads.redact_request`).
- [ ] Le flux entrant passe par `restore()`, et la restauration se fait avant
      toute autre opération.
- [ ] Les outils d'egress sont identifiés via `policy.should_restore_args()`, pas
      par une liste maison.
- [ ] Aucune exception ne peut s'échapper vers l'hôte ; la direction sortante
      abandonne le résultat plutôt que de le laisser passer en clair.
- [ ] `settings.block` est respecté.
- [ ] La sortie est déterministe pour une entrée identique (prompt caching).
- [ ] Les journaux ne contiennent que des compteurs.
- [ ] Un test rejoue `tests/fixtures.py::ALL_FIXTURES` à travers le connecteur et
      vérifie qu'aucun `secret` déclaré ne survit. C'est le test qui compte ;
      les autres vérifient des mécanismes, celui-ci vérifie la propriété.
