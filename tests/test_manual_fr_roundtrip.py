"""End-to-end FR document check — synthetic PII only, nothing leaves this box.

Complements ``test_leak.py``: the shared fixtures cover invoices and statements,
this one is a single dense insurance letter carrying the formats that escaped in
earlier rounds — dossier reference, BIC, driving-licence number, postal code,
hyphenated compound names — plus an IP. It asserts both halves of the contract:
no real value survives redaction, and ``restore()`` rebuilds the input exactly.
"""

from __future__ import annotations

import re

from piiredact import Redactor

TEXT = """Objet : régularisation dossier sinistre n° 2024-DA-88213

Bonjour Madame Christelle Vandenberghe-Moreau,

Suite à notre entretien du 12 mars, je confirme la prise en charge du dossier
de M. Jean-Baptiste Le Goff, domicilié 47 bis rue des Petites-Écuries,
75010 Paris. Son épouse, Mme Solène Attia, est co-assurée sur le contrat.

Coordonnées de contact :
  - téléphone fixe : 01 45 22 89 07
  - portable : +33 6 12 34 56 78
  - courriel : jb.legoff@exemple-mutuelle.fr
  - courriel secondaire : solene.attia1987@laposte.net

Éléments administratifs transmis par le service :
  - numéro de sécurité sociale : 1 87 03 75 116 042 39
  - IBAN de remboursement : FR76 3000 6000 0112 3456 7890 189
  - BIC : AGRIFRPP882
  - carte bancaire utilisée pour la cotisation : 4970 1012 3456 7893
  - numéro SIRET du cabinet : 552 100 554 00021
  - permis de conduire n° 13AA00002
  - plaque du véhicule : AB-123-CD

Le remboursement de 1 234,56 € sera viré le 30/04/2024. Merci de confirmer à
Christelle Vandenberghe-Moreau ou directement à jb.legoff@exemple-mutuelle.fr.

Connexion au portail depuis 192.168.14.72 le 12/03/2024 à 09:41.

Bien cordialement,
Jean-Baptiste Le Goff
"""

# Every literal that must never appear in the pseudonymised text.
SECRETS = [
    "2024-DA-88213",
    "Christelle Vandenberghe-Moreau",
    "Jean-Baptiste Le Goff",
    "Solène Attia",
    "01 45 22 89 07",
    "+33 6 12 34 56 78",
    "jb.legoff@exemple-mutuelle.fr",
    "solene.attia1987@laposte.net",
    "1 87 03 75 116 042 39",
    "FR76 3000 6000 0112 3456 7890 189",
    "AGRIFRPP882",
    "4970 1012 3456 7893",
    "552 100 554 00021",
    "13AA00002",
    "AB-123-CD",
    "192.168.14.72",
    "47 bis rue des Petites-Écuries",
]

FRAGMENTS = ("Vandenberghe", "Christelle", "Baptiste", "Solène", "Attia", "Goff")


def test_manual_fr_roundtrip(strict_redactor: Redactor) -> None:
    result = strict_redactor.redact(TEXT)
    safe = result.text

    for secret in SECRETS:
        assert secret not in safe, f"fuite littérale : {secret!r}"

    # A leak can also survive as a fragment: check each name token on its own.
    for token in FRAGMENTS:
        assert not re.search(rf"\b{re.escape(token)}\b", safe), f"fuite : {token!r}"

    # Digit runs long enough to be an identifier must all be placeholders.
    residual = re.findall(r"\d[\d ]{8,}\d", safe)
    assert not residual, f"suites de chiffres résiduelles : {residual}"

    assert strict_redactor.restore(safe) == TEXT


def test_manual_fr_roundtrip_balanced(redactor: Redactor) -> None:
    """The shipped default profile must not leak either — only AMOUNT/DATE/IP
    are meant to survive it."""
    result = redactor.redact(TEXT)
    safe = result.text

    for secret in SECRETS:
        if secret == "192.168.14.72":  # IP is a strict-profile quasi-identifier
            continue
        assert secret not in safe, f"fuite littérale (balanced) : {secret!r}"
    for token in FRAGMENTS:
        assert not re.search(rf"\b{re.escape(token)}\b", safe), f"fuite : {token!r}"
    assert redactor.restore(safe) == TEXT
