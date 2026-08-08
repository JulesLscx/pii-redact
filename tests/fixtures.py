"""Realistic French PII fixtures and the exact values that must never leak.

Each fixture pairs a document with the *literal* strings a leak test asserts
against. Keeping the values next to the document (rather than re-deriving them
with a regex) is deliberate: the test must fail if the engine's own patterns
are wrong, so it cannot be allowed to reuse them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class Fixture:
    """A document plus the raw values that must not survive redaction."""

    name: str
    text: str
    secrets: List[str]
    #: Values the deterministic layers are *not* expected to catch on their own
    #: (documented limitations, exercised by ``test_known_limitations``).
    unclaimed: List[str] = field(default_factory=list)


FACTURE = Fixture(
    name="facture",
    text="""FACTURE N° 2025-0042
Émetteur : SARL Dupont Toitures — SIRET 552 100 554 00021 — TVA FR32 552 100 554
7 avenue du Général Leclerc, 69300 Caluire-et-Cuire
Contact : contact@dupont-toitures.fr — 04 78 22 11 09

Destinataire : Amélie Roux
12 bis rue des Lilas, 69007 Lyon
amelie.roux@example.fr — 06 12 34 56 78

Réf. client n° CL-448192
Prestation : réfection toiture, du 03/02/2025 au 12/03/2025.
Montant HT : 5 400,00 € — TVA 20% : 1 080,00 € — Total TTC : 6 480,00 €.
Règlement par virement : IBAN FR76 3000 4000 0512 3456 7890 143.
Carte enregistrée : 4970 1234 5678 9012.
""",
    secrets=[
        "Dupont Toitures",
        "552 100 554 00021",
        "contact@dupont-toitures.fr",
        "04 78 22 11 09",
        "Amélie Roux",
        "12 bis rue des Lilas",
        "amelie.roux@example.fr",
        "06 12 34 56 78",
        "CL-448192",
        "FR76 3000 4000 0512 3456 7890 143",
        "4970 1234 5678 9012",
        "69300",
        "69007",
    ],
)

RELEVE = Fixture(
    name="releve-bancaire",
    text="""RELEVÉ DE COMPTE — Banque Crédit Rhodanien
Titulaire : Amélie Roux
Compte n° 30004000512345678
IBAN : FR76 3000 4000 0512 3456 7890 143
Adresse : 12 bis rue des Lilas, 69007 Lyon

02/03/2025  VIR SEPA M. Jean-Pierre Martin          + 1 250,00 €
05/03/2025  PRLV Mutuelle Saint-Éloi                  - 89,90 €.
09/03/2025  CB 4970 1234 5678 9012 chez Leroy Merlin  - 342,15 €,
12/03/2025  VIR recu de contact@dupont-toitures.fr   + 6 480,00 €;
Solde au 31/03/2025 : 12 843,27 €.
""",
    secrets=[
        "Amélie Roux",
        "30004000512345678",
        "FR76 3000 4000 0512 3456 7890 143",
        "12 bis rue des Lilas",
        "Jean-Pierre Martin",
        "4970 1234 5678 9012",
        "contact@dupont-toitures.fr",
        "69007",
    ],
)

AVIS_IMPOSITION = Fixture(
    name="avis-imposition",
    text="""AVIS D'IMPÔT 2025 — Revenus 2024
Nom et prénom : Roux Amélie
N° fiscal : 2512345678901
Numéro de sécurité sociale : 2 84 09 69 123 456 78
Adresse : 12 bis rue des Lilas, 69007 Lyon
Téléphone : 06 12 34 56 78
Courriel : amelie.roux@example.fr

Revenu fiscal de référence : 41 250,00 €.
Impôt sur le revenu net : 4 812,00 €,
Date limite de paiement : 15/09/2025;
Véhicule déclaré : AB-123-CD.
""",
    secrets=[
        "Roux Amélie",
        "2 84 09 69 123 456 78",
        "12 bis rue des Lilas",
        "06 12 34 56 78",
        "amelie.roux@example.fr",
        "AB-123-CD",
        "69007",
    ],
    # The fiscal number has no dedicated rule; it is 13 digits, which is
    # deliberately not covered by SIRET (14) or NIR (13+2 with a structure).
    unclaimed=["2512345678901"],
)

NOTE_DE_COURS = Fixture(
    name="note-de-cours",
    text="""Compte rendu — réunion du 12/03/2025
Présents : Mme Amélie Roux (direction), M. Jean-Pierre Martin (comptabilité),
Dr Sophie Vasseur (médecine du travail).

Actions :
- Amélie Roux relance la SARL Dupont Toitures avant le 20/03/2025.
- Envoyer le devis à contact@dupont-toitures.fr et en copie à
  j-p.martin@example.org.
- Rappeler le cabinet Vasseur au 04 72 00 11 22.
Budget validé : 6 480,00 €.
""",
    secrets=[
        "Amélie Roux",
        "Jean-Pierre Martin",
        "Sophie Vasseur",
        "contact@dupont-toitures.fr",
        "j-p.martin@example.org",
        "04 72 00 11 22",
    ],
)

ALL_FIXTURES: List[Fixture] = [FACTURE, RELEVE, AVIS_IMPOSITION, NOTE_DE_COURS]

FIXTURES_BY_NAME: Dict[str, Fixture] = {f.name: f for f in ALL_FIXTURES}

#: Values that must be redacted even when glued to punctuation. This is the
#: regression corpus for the ``\\b``-tail trap: every entry is a real value
#: immediately followed by a character that would break a ``\\b`` anchor.
PUNCTUATED_CASES = [
    ("Total : 1 234,56 €.", "1 234,56 €"),
    ("Total : 1 234,56 €,", "1 234,56 €"),
    ("Total : 1 234,56 €;", "1 234,56 €"),
    ("(montant 890,00 €)", "890,00 €"),
    ("Écrire à jean@example.fr.", "jean@example.fr"),
    ("Écrire à jean@example.fr,", "jean@example.fr"),
    ("Écrire à jean@example.fr;", "jean@example.fr"),
    ("Contact (jean@example.fr)", "jean@example.fr"),
    ("Appelez le 06 12 34 56 78.", "06 12 34 56 78"),
    ("Appelez le 06 12 34 56 78,", "06 12 34 56 78"),
    ("IBAN FR76 3000 4000 0512 3456 7890 143.", "FR76 3000 4000 0512 3456 7890 143"),
    ("SIRET 552 100 554 00021.", "552 100 554 00021"),
    ("Carte 4970 1234 5678 9012.", "4970 1234 5678 9012"),
    ("Code postal 69007.", "69007"),
    ("Plaque AB-123-CD.", "AB-123-CD"),
]
