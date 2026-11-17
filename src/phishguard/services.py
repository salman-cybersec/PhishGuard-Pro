
from copy import deepcopy


SERVICES = {
    "facebook": {
        "name": "Facebook",
        "scenarios": [
            "account_security",
            "free_followers_awareness",
        ],
    },
    "instagram": {
        "name": "Instagram",
        "scenarios": [
            "account_security",
            "free_followers_awareness",
        ],
    },
    "tiktok": {
        "name": "TikTok",
        "scenarios": [
            "account_security",
            "free_followers_awareness",
        ],
    },
    "snapchat": {
        "name": "Snapchat",
        "scenarios": [
            "account_security",
            "free_offers_awareness",
        ],
    },
    "paypal": {
        "name": "PayPal",
        "scenarios": [
            "payment_security",
            "account_security",
        ],
    },
    "google": {
        "name": "Google",
        "scenarios": [
            "account_security",
            "account_recovery_awareness",
        ],
    },
    "microsoft": {
        "name": "Microsoft",
        "scenarios": [
            "account_security",
            "subscription_awareness",
        ],
    },
    "netflix": {
        "name": "Netflix",
        "scenarios": [
            "subscription_awareness",
            "account_security",
        ],
    },
    "linkedin": {
        "name": "LinkedIn",
        "scenarios": [
            "account_security",
            "job_offer_awareness",
        ],
    },
    "x": {
        "name": "X",
        "scenarios": [
            "account_security",
            "verification_awareness",
        ],
    },
    "amazon": {
        "name": "Amazon",
        "scenarios": [
            "shopping_security",
            "delivery_awareness",
        ],
    },
    "apple": {
        "name": "Apple",
        "scenarios": [
            "account_security",
            "account_recovery_awareness",
        ],
    },
    "discord": {
        "name": "Discord",
        "scenarios": [
            "account_security",
            "free_offer_awareness",
        ],
    },
    "telegram": {
        "name": "Telegram",
        "scenarios": [
            "account_security",
            "verification_awareness",
        ],
    },
    "steam": {
        "name": "Steam",
        "scenarios": [
            "gaming_security",
            "free_offer_awareness",
        ],
    },
    "spotify": {
        "name": "Spotify",
        "scenarios": [
            "subscription_awareness",
            "account_security",
        ],
    },
    "yahoo": {
        "name": "Yahoo",
        "scenarios": [
            "account_security",
            "account_recovery_awareness",
        ],
    },
    "reddit": {
        "name": "Reddit",
        "scenarios": [
            "account_security",
            "community_safety",
        ],
    },
    "pinterest": {
        "name": "Pinterest",
        "scenarios": [
            "account_security",
            "free_offer_awareness",
        ],
    },
    "twitch": {
        "name": "Twitch",
        "scenarios": [
            "account_security",
            "gaming_security",
        ],
    },
    "zoom": {
        "name": "Zoom",
        "scenarios": [
            "account_security",
            "verification_awareness",
        ],
    },
    "dropbox": {
        "name": "Dropbox",
        "scenarios": [
            "account_security",
            "account_recovery_awareness",
        ],
    },
    "github": {
        "name": "GitHub",
        "scenarios": [
            "account_security",
            "verification_awareness",
        ],
    },

}


SCENARIO_LABELS = {
    "account_security": "Account Security Awareness",
    "free_followers_awareness": "Free Followers Awareness",
    "free_offers_awareness": "Free Offers Awareness",
    "payment_security": "Payment Security Awareness",
    "account_recovery_awareness": "Account Recovery Awareness",
    "subscription_awareness": "Subscription Awareness",
    "job_offer_awareness": "Job Offer Awareness",
    "verification_awareness": "Verification Awareness",
    "shopping_security": "Shopping Security Awareness",
    "delivery_awareness": "Delivery Awareness",
    "gaming_security": "Gaming Security Awareness",
    "community_safety": "Community Safety Awareness",
}


def list_services():
    return [
        {
            "id": service_id,
            "name": details["name"],
            "scenarios": deepcopy(details["scenarios"]),
        }
        for service_id, details in SERVICES.items()
    ]


def get_service(service_id):
    if not isinstance(service_id, str):
        raise ValueError("Service ID must be text.")

    normalized = service_id.strip().lower()

    if normalized not in SERVICES:
        raise ValueError("Unknown service.")

    return {
        "id": normalized,
        **deepcopy(SERVICES[normalized]),
    }


def get_service_scenarios(service_id):
    service = get_service(service_id)

    return [
        {
            "id": scenario_id,
            "name": SCENARIO_LABELS[scenario_id],
        }
        for scenario_id in service["scenarios"]
    ]


def validate_scenario(service_id, scenario_id):
    if not isinstance(scenario_id, str):
        raise ValueError("Scenario ID must be text.")

    service = get_service(service_id)
    normalized = scenario_id.strip().lower()

    if normalized not in service["scenarios"]:
        raise ValueError(
            "This scenario is not available for the selected service."
        )

    return {
        "service_id": service["id"],
        "scenario_id": normalized,
        "scenario_name": SCENARIO_LABELS[normalized],
    }
