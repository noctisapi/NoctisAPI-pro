from __future__ import annotations

import random

_FIRST_NAMES = (
    "Lucas",
    "Mateo",
    "Daniel",
    "Adrian",
    "Nicolas",
    "Sofia",
    "Valeria",
    "Clara",
    "Paula",
    "Marta",
    "Irene",
    "Elena",
    "Julian",
    "Camila",
    "Sara",
    "Diego",
)

_LAST_NAMES = (
    "Navarro",
    "Molina",
    "Castro",
    "Ortega",
    "Vega",
    "Santos",
    "Ruiz",
    "Paredes",
    "Lozano",
    "Ramos",
    "Cabrera",
    "Serrano",
    "Campos",
    "Herrera",
    "Suarez",
    "Fuentes",
)

_EMAIL_DOMAINS = (
    "northstar-logistics.com",
    "harborpay.io",
    "pinecresthealth.co",
    "westbridge-retail.com",
    "silverlineapps.com",
    "aureliadata.io",
    "redcliffsystems.com",
    "blueharborcommerce.com",
)

_MERCHANT_NAMES = (
    "Northwind Freight",
    "Blue Cedar Market",
    "Harbor Point Pharmacy",
    "Summit Office Supply",
    "Red Oak Travel",
    "Clearwater Home Goods",
    "Ironwood Fitness",
    "Lakeside Books",
)


def fake_person_identity(rng: random.Random) -> dict[str, str]:
    first = rng.choice(_FIRST_NAMES)
    last = rng.choice(_LAST_NAMES)
    full_name = f"{first} {last}"

    email_local = rng.choice(
        (
            f"{first}.{last}",
            f"{first[0]}.{last}",
            f"{first}_{last}",
            f"{first}{last}",
        )
    ).lower()
    username = rng.choice(
        (
            f"{first.lower()}.{last.lower()}",
            f"{first[0].lower()}{last.lower()}",
            f"{first.lower()}_{last.lower()}",
            f"{first.lower()}{last.lower()}",
        )
    )

    return {
        "first_name": first,
        "last_name": last,
        "name": full_name,
        "email": f"{email_local}@{rng.choice(_EMAIL_DOMAINS)}",
        "username": username,
    }


def fake_merchant_name(rng: random.Random) -> str:
    return rng.choice(_MERCHANT_NAMES)
