
from html import escape

from phishguard.services import (
    get_service,
    validate_scenario,
)


TEMPLATES = {
    "account_security": {
        "title": "Account Security Awareness",
        "message": (
            "Learn how to identify suspicious account "
            "security messages and unexpected login requests."
        ),
        "action": "Review Security Tips",
    },
    "free_followers_awareness": {
        "title": "Free Followers Awareness",
        "message": (
            "Unrealistic follower offers can be used to "
            "trick people into visiting unsafe websites."
        ),
        "action": "Review Safety Tips",
    },
    "free_offers_awareness": {
        "title": "Free Offers Awareness",
        "message": (
            "Unexpected free offers may contain suspicious "
            "links or misleading requests."
        ),
        "action": "Review Offer Safety",
    },
    "payment_security": {
        "title": "Payment Security Awareness",
        "message": (
            "Always verify payment requests and confirm "
            "the destination before taking action."
        ),
        "action": "Review Payment Safety",
    },
    "account_recovery_awareness": {
        "title": "Account Recovery Awareness",
        "message": (
            "Be careful with unexpected account recovery "
            "messages and verification requests."
        ),
        "action": "Review Recovery Safety",
    },
    "subscription_awareness": {
        "title": "Subscription Security Awareness",
        "message": (
            "Check subscription notifications through "
            "official channels before responding."
        ),
        "action": "Review Subscription Safety",
    },
    "job_offer_awareness": {
        "title": "Job Offer Awareness",
        "message": (
            "Verify recruiters, company identities and "
            "unexpected job opportunities."
        ),
        "action": "Review Job Safety",
    },
    "verification_awareness": {
        "title": "Verification Security Awareness",
        "message": (
            "Never share verification codes with someone "
            who contacts you unexpectedly."
        ),
        "action": "Review Verification Safety",
    },
    "shopping_security": {
        "title": "Shopping Security Awareness",
        "message": (
            "Check website addresses, sellers and payment "
            "requests before making online purchases."
        ),
        "action": "Review Shopping Safety",
    },
    "delivery_awareness": {
        "title": "Delivery Message Awareness",
        "message": (
            "Unexpected delivery messages may contain "
            "misleading links or payment requests."
        ),
        "action": "Review Delivery Safety",
    },
    "gaming_security": {
        "title": "Gaming Security Awareness",
        "message": (
            "Protect gaming accounts and be cautious "
            "of suspicious rewards and offers."
        ),
        "action": "Review Gaming Safety",
    },
    "community_safety": {
        "title": "Community Safety Awareness",
        "message": (
            "Check suspicious messages, links and "
            "unexpected requests in online communities."
        ),
        "action": "Review Community Safety",
    },
}


def get_template(service_id, scenario_id):
    service = get_service(service_id)
    scenario = validate_scenario(service_id, scenario_id)

    template = TEMPLATES.get(scenario["scenario_id"])

    if template is None:
        raise ValueError("Awareness template is unavailable.")

    return {
        "service_id": service["id"],
        "service_name": service["name"],
        "scenario_id": scenario["scenario_id"],
        "scenario_name": scenario["scenario_name"],
        "title": template["title"],
        "message": template["message"],
        "action": template["action"],
    }


def render_awareness_page(service_id, scenario_id):
    template = get_template(service_id, scenario_id)

    service_name = escape(template["service_name"])
    title = escape(template["title"])
    message = escape(template["message"])
    action = escape(template["action"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
* {{
    box-sizing: border-box;
}}
body {{
    margin: 0;
    padding: 24px;
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: #f4f7fb;
    color: #1f2937;
    font-family: Arial, sans-serif;
}}
.card {{
    width: 100%;
    max-width: 560px;
    padding: 32px;
    background: white;
    border: 1px solid #dce3ec;
    border-radius: 14px;
    box-shadow: 0 12px 35px rgba(0,0,0,.06);
}}
.notice {{
    padding: 12px;
    background: #eaf3ff;
    border-left: 4px solid #2563eb;
    border-radius: 5px;
    color: #174ea6;
    font-weight: bold;
}}
h1 {{
    margin-top: 24px;
    font-size: 26px;
}}
p {{
    line-height: 1.7;
}}
.service {{
    color: #64748b;
    font-size: 14px;
}}
button {{
    margin-top: 16px;
    padding: 12px 18px;
    border: 0;
    border-radius: 7px;
    background: #2563eb;
    color: white;
    font-size: 15px;
}}
.footer {{
    margin-top: 24px;
    color: #64748b;
    font-size: 12px;
}}
</style>
</head>
<body>
<main class="card">
    <div class="notice">
        Authorized Security Awareness Simulation
    </div>
    <p class="service">{service_name} awareness scenario</p>
    <h1>{title}</h1>
    <p>{message}</p>
    <button type="button" disabled>{action}</button>
    <div class="footer">
        PhishGuard Pro | Educational training page.
        No passwords or verification codes are requested.
    </div>
</main>
</body>
</html>"""
