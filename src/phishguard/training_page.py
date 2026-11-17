
from html import escape

from phishguard.awareness_templates import get_template


def render_training_page(
    campaign_name: str,
    campaign_id: int,
    service_id: str | None = None,
    scenario_id: str | None = None,
) -> str:
    if not isinstance(campaign_id, int) or campaign_id <= 0:
        raise ValueError("Invalid campaign ID.")

    if not isinstance(campaign_name, str):
        raise ValueError("Invalid campaign name.")

    campaign_name = campaign_name.strip()

    if not campaign_name or len(campaign_name) > 100:
        raise ValueError(
            "Campaign name must contain 1-100 characters."
        )

    if (service_id is None) != (scenario_id is None):
        raise ValueError(
            "Service and scenario must be provided together."
        )

    safe_name = escape(campaign_name)

    awareness_section = ""

    if service_id is not None:
        template = get_template(service_id, scenario_id)

        safe_service = escape(template["service_name"])
        safe_title = escape(template["title"])
        safe_message = escape(template["message"])
        safe_action = escape(template["action"])

        awareness_section = f"""
        <section class="awareness">
            <p class="service">{safe_service} awareness scenario</p>
            <h3>{safe_title}</h3>
            <p>{safe_message}</p>
            <p class="action-label">{safe_action}</p>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Awareness Training</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #f4f6f9;
            margin: 0;
            padding: 30px 15px;
            color: #222;
        }}
        .container {{
            max-width: 480px;
            margin: 30px auto;
            padding: 28px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.08);
        }}
        .notice {{
            padding: 14px;
            background: #eaf3ff;
            border-left: 4px solid #2673d9;
            margin-bottom: 22px;
            line-height: 1.5;
        }}
        .awareness {{
            padding: 16px;
            margin: 18px 0;
            background: #f8fafc;
            border: 1px solid #dce3ec;
            border-radius: 8px;
            line-height: 1.6;
        }}
        .service, .action-label {{
            color: #52647a;
            font-size: 13px;
        }}
        label {{
            display: block;
            margin: 14px 0 7px;
        }}
        input[type="text"] {{
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            border: 1px solid #ccc;
            border-radius: 6px;
        }}
        .consent {{
            display: flex;
            gap: 9px;
            align-items: flex-start;
            line-height: 1.4;
            margin: 14px 0;
        }}
        button {{
            width: 100%;
            padding: 13px;
            background: #1769d2;
            color: white;
            border: 0;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 12px;
        }}
    </style>
</head>
<body>
    <main class="container">
        <h2>Security Awareness Training</h2>

        <div class="notice">
            This is an authorized security-awareness simulation.
            No real passwords or verification codes are requested
            or collected. Review the data collection choices below.
        </div>

        <h3>{safe_name}</h3>

        {awareness_section}

        <form method="post" action="/training/submit">
            <input type="hidden"
                   name="campaign_id"
                   value="{campaign_id}">

            <label for="participant_name">
                Participant name or username
            </label>

            <input
                type="text"
                id="participant_name"
                name="participant_name"
                maxlength="100"
                required
                autocomplete="off"
            >

            <label class="consent">
                <input type="checkbox" name="consent_ip" value="yes">
                <span>I consent to collection of my public IP address.</span>
            </label>

            <label class="consent">
                <input type="checkbox" name="consent_device" value="yes">
                <span>
                    I consent to collection of my browser and device
                    information.
                </span>
            </label>

            <button type="submit">Continue</button>
        </form>
    </main>
</body>
</html>"""
