"""French pack — conventions françaises.

Couvre : NIR (sécurité sociale), SIRET/SIREN et TVA intracommunautaire, numéro
de compte contextuel, téléphone métropolitain, adresse postale, code postal,
immatriculation, personnes ancrées par civilité ou par champ, organisations
ancrées par forme juridique, montants en euros et dates.

Ce qui a la même forme partout (email, IBAN, carte) vit dans
:mod:`piiredact.lang.common`.
"""

from __future__ import annotations

import re
from typing import Tuple

from ..rules import Priority, Rule, compile_pattern
from ..types import EntityType

LANG = "fr"

#: Modèle spaCy utilisé quand la couche NER est active sans modèle configuré.
NER_MODEL = "fr_core_news_sm"

_MONTHS = (
    "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|"
    "septembre|octobre|novembre|décembre|decembre"
)

_TITLES = r"(?:M\.|MM\.|Mme|Mmes|Mlle|Dr|Pr|Me|Monsieur|Madame|Mademoiselle|Maître|Maitre)"

# La majuscule initiale est imposée via un ``(?-i:...)`` local : les règles qui
# embarquent cette chaîne sont compilées avec ``re.IGNORECASE`` pour leur ancre
# ("banque", "titulaire"). Sans le drapeau local, la majuscule cesse d'être une
# contrainte et la chaîne déborde sur des mots ordinaires en minuscules.
_NAME_WORD = r"(?-i:[A-ZÀ-Ý])[\w'’\-]{1,30}"
# ``[ \t]+`` rather than ``\s+``: a real name never spans a line break, but a
# field label on the following line ("Titulaire : Amélie Roux\nAdresse : …")
# starts with a capital too and would otherwise be swallowed into the chain.
_NAME_CHAIN = rf"{_NAME_WORD}(?:[ \t]+(?:de|du|des|le|la|van|von|d'|l')?[ \t]*{_NAME_WORD}){{0,3}}"

RULES: Tuple[Rule, ...] = (
    # -- identifiants nationaux et fiscaux -----------------------------------
    Rule(
        EntityType.NATIONAL_ID,
        # NIR : sexe, année, mois, département (2A/2B pour la Corse), commune,
        # ordre, puis clé de contrôle optionnelle.
        compile_pattern(
            r"(?<!\d)[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?"
            r"\d{3}\s?\d{3}(?:\s?\d{2})?(?!\d)"
        ),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.TAX_ID,
        # SIRET (14 chiffres, groupés ou non). Les gardes sur les chiffres
        # empêchent de mordre un fragment de carte à 16 chiffres.
        compile_pattern(r"(?<!\d)\d{3}[ ]\d{3}[ ]\d{3}[ ]\d{5}(?!\d)|(?<!\d)\d{14}(?!\d)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.TAX_ID,
        # TVA intracommunautaire française.
        compile_pattern(r"(?<!\w)FR[ ]?[0-9A-Z]{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}(?!\w)"),
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.NATIONAL_ID,
        # Permis de conduire. Le format a changé plusieurs fois (12 chiffres
        # avant 2013, puis 2 chiffres + 2 lettres + 5 chiffres), donc la règle
        # s'ancre sur le libellé : une règle de forme pure ramasserait la
        # moitié des références internes d'un document administratif.
        compile_pattern(
            r"(?<!\w)permis(?:\s+de\s+conduire)?\s*(?:n[°ºo]|num[ée]ro)?\s*:?\s*"
            r"((?-i:(?=[A-Z0-9]*\d)[A-Z0-9]{8,15}))(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    Rule(
        EntityType.ACCOUNT,
        compile_pattern(
            r"(?:compte|contrat|dossier|client|adh[ée]rent|assur[ée]|police|"
            r"facture|r[ée]f[ée]rence|r[ée]f)\s*"
            r"(?:bancaire\s*)?"
            # Un qualificatif peut s'intercaler ("dossier sinistre n° …").
            # Inoffensif depuis que le groupe capturant exige majuscules et
            # chiffre : un mot ordinaire ne peut plus y passer.
            r"(?:(?-i:[a-zà-ÿ]{2,15})\s+)?"
            r"(?:n[°ºo]|num[ée]ro)?\s*:?\s*"
            # Même précaution que ``_NAME_WORD`` : la règle est compilée avec
            # ``re.IGNORECASE`` pour son ancre, ce qui ferait tomber la
            # contrainte de casse et laisserait le groupe avaler le mot suivant
            # ("dossier sinistre n° …" → "sinistre"). Le digit obligatoire
            # écarte en plus les libellés tout en majuscules.
            r"((?-i:(?=[A-Z0-9\-]*\d)[A-Z0-9][A-Z0-9\-]{5,19}))(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.STRUCTURED,
        lang=LANG,
    ),
    # -- contact -------------------------------------------------------------
    Rule(
        EntityType.PHONE,
        compile_pattern(r"(?<![\d+])(?:\+33[ .\-]?|0)[1-9](?:[ .\-]?\d{2}){4}(?!\d)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    Rule(
        EntityType.PLATE,
        compile_pattern(r"(?<![A-Z0-9\-])[A-Z]{2}-\d{3}-[A-Z]{2}(?!\w)"),
        priority=Priority.CONTACT,
        lang=LANG,
    ),
    # -- adresse postale -----------------------------------------------------
    Rule(
        EntityType.ADDR,
        compile_pattern(
            r"(?<!\w)\d{1,4}(?:\s?(?:bis|ter|quater))?[,]?\s+"
            r"(?:rue|avenue|av\.|boulevard|bd|impasse|chemin|all[ée]e|place|"
            r"route|quai|square|lieu-dit|r[ée]sidence|voie|cours|passage)\s+"
            # Les guillemets sont exclus pour qu'une rédaction dans un résultat
            # d'outil encodé en JSON ne puisse jamais avaler un guillemet
            # fermant et corrompre l'enveloppe.
            r"[^\n,;\"']{2,60}?(?=\s*(?:,|;|\n|$))",
            re.I,
        ),
        priority=Priority.ADDRESS,
        lang=LANG,
    ),
    # -- personnes -----------------------------------------------------------
    Rule(
        EntityType.PERSON,
        compile_pattern(rf"(?<!\w){_TITLES}\s+({_NAME_CHAIN})(?!\w)"),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    Rule(
        EntityType.PERSON,
        compile_pattern(
            r"(?<!\w)(?:nom(?:\s+et\s+pr[ée]nom)?|pr[ée]nom|titulaire|"
            r"b[ée]n[ée]ficiaire|destinataire|exp[ée]diteur|sign[ée]|"
            r"[ée]metteur|locataire|patient|[ée]l[èe]ve|contact)"
            rf"\s*[:\-—]\s*({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    # -- organisations -------------------------------------------------------
    Rule(
        EntityType.ORG,
        # En français la forme juridique précède le nom, contrairement à
        # l'anglais.
        compile_pattern(
            r"(?<!\w)(?:SARL|SASU|SAS|SA|EURL|EIRL|SCI|SNC|SCCV|GIE|SCOP|SCP|"
            r"banque|caisse|mutuelle|association|cabinet)\b"
            rf"\s+({_NAME_CHAIN})(?!\w)",
            re.I,
        ),
        group=1,
        priority=Priority.NAME,
        lang=LANG,
    ),
    # -- quasi-identifiants (profil strict uniquement) -----------------------
    Rule(
        EntityType.AMOUNT,
        compile_pattern(
            # Le français utilise l'espace insécable (U+00A0) et l'espace
            # insécable fine (U+202F) comme séparateur de milliers.
            r"(?<![\w,.])\d{1,3}(?:[ .  ]\d{3})*(?:[,.]\d{2})?\s?(?:€|EUR|euros?)(?!\w)"
            r"|€\s?\d{1,3}(?:[ .  ]\d{3})*(?:[,.]\d{2})?(?!\w)",
            re.I,
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
    Rule(
        EntityType.DATE,
        compile_pattern(
            r"(?<!\d)\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}(?!\d)"
            rf"|(?<!\w)\d{{1,2}}(?:er)?\s+(?:{_MONTHS})\s+\d{{4}}(?!\d)",
            re.I,
        ),
        priority=Priority.QUASI,
        lang=LANG,
    ),
    # -- en dernier, sur ce qu'aucune autre règle n'a réclamé ----------------
    Rule(
        EntityType.POSTAL,
        # Les gardes portent sur ``[\w-]`` et non sur ``\d`` seul : sans elles,
        # les cinq derniers chiffres d'un identifiant alphanumérique
        # ("13AA00002", "2024-DA-88213") sont pris pour un code postal, ce qui
        # coupe le jeton en deux et le rend illisible pour le modèle.
        compile_pattern(r"(?<![\w-])\d{5}(?![\w-])"),
        priority=Priority.GENERIC,
        lang=LANG,
    ),
)
