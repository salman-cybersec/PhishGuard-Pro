import re
from http.cookies import SimpleCookie


SIGNATURES = [
    # Programming languages / server runtimes
    ("PHP", "Language", [
        (r"(?i)x-powered-by:\s*php/?([\d.]+)?", "X-Powered-By header"),
        (r"(?i)phpsessid", "PHP session cookie"),
        (r"(?i)\.php(?:[/?#]|$)", "PHP endpoint reference"),
    ]),
    ("ASP.NET", "Language / Runtime", [
        (r"(?i)x-powered-by:\s*asp\.net", "X-Powered-By header"),
        (r"(?i)asp\.net", "ASP.NET fingerprint"),
        (r"(?i)\.aspx(?:[/?#]|$)", "ASP.NET endpoint"),
        (r"(?i)asp\.net_sessionid", "ASP.NET session cookie"),
    ]),
    ("Java / JSP", "Language / Runtime", [
        (r"(?i)jsessionid", "Java session cookie"),
        (r"(?i)\.jsp(?:[/?#]|$)", "JSP endpoint reference"),
        (r"(?i)x-powered-by:\s*servlet", "Servlet response header"),
    ]),
    ("Python", "Language", [
        (r"(?i)x-powered-by:\s*python", "X-Powered-By header"),
        (r"(?i)werkzeug", "Werkzeug response fingerprint"),
        (r"(?i)django", "Django response fingerprint"),
    ]),
    ("Ruby", "Language", [
        (r"(?i)_session_id", "Ruby session cookie indicator"),
        (r"(?i)x-powered-by:\s*phusion passenger", "Passenger server header"),
    ]),
    ("Node.js", "Runtime", [
        (r"(?i)x-powered-by:\s*express", "Express response header"),
        (r"(?i)x-powered-by:\s*next\.js", "Next.js response header"),
    ]),
    ("Go", "Language", [
        (r"(?i)server:\s*go", "Server response header"),
    ]),

    # CMS / ecommerce
    ("WordPress", "CMS", [
        (r"(?i)/wp-content/", "WordPress content path"),
        (r"(?i)/wp-includes/", "WordPress core path"),
        (r"(?i)name=[\"']generator[\"'][^>]*wordpress", "Generator metadata"),
        (r"(?i)wp-json", "WordPress REST API reference"),
    ]),
    ("Joomla", "CMS", [
        (r"(?i)/media/system/js/", "Joomla asset path"),
        (r"(?i)content=\"joomla!", "Joomla generator metadata"),
    ]),
    ("Drupal", "CMS", [
        (r"(?i)/sites/default/files/", "Drupal public files path"),
        (r"(?i)drupalSettings", "Drupal JavaScript settings"),
        (r"(?i)content=\"drupal", "Drupal generator metadata"),
    ]),
    ("Shopify", "E-commerce", [
        (r"(?i)cdn\.shopify\.com", "Shopify CDN reference"),
        (r"(?i)myshopify\.com", "Shopify domain reference"),
        (r"(?i)shopify\.theme", "Shopify theme object"),
    ]),
    ("Magento", "E-commerce", [
        (r"(?i)/static/frontend/", "Magento frontend asset path"),
        (r"(?i)mage/cookies", "Magento JavaScript module"),
    ]),
    ("Wix", "Website Platform", [
        (r"(?i)wixstatic\.com", "Wix asset host"),
        (r"(?i)wix\.com", "Wix platform reference"),
    ]),
    ("Webflow", "Website Platform", [
        (r"(?i)webflow\.com", "Webflow platform reference"),
        (r"(?i)data-wf-page", "Webflow page attribute"),
    ]),
    ("Squarespace", "Website Platform", [
        (r"(?i)squarespace\.com", "Squarespace asset reference"),
        (r"(?i)squarespace-cdn\.com", "Squarespace CDN"),
    ]),

    # Frontend frameworks / libraries
    ("React", "Frontend Framework", [
        (r"(?i)__REACT", "React runtime marker"),
        (r"(?i)data-reactroot", "React root attribute"),
        (r"(?i)/_next/static/", "Next.js React asset path"),
        (r"(?i)react(?:-dom)?(?:\.production)?\.min\.js", "React script reference"),
    ]),
    ("Next.js", "Frontend Framework", [
        (r"(?i)/_next/static/", "Next.js static asset path"),
        (r"(?i)__NEXT_DATA__", "Next.js page data"),
    ]),
    ("Angular", "Frontend Framework", [
        (r"(?i)ng-version=", "Angular version attribute"),
        (r"(?i)angular(?:\.min)?\.js", "Angular script reference"),
    ]),
    ("Vue.js", "Frontend Framework", [
        (r"(?i)data-v-[a-f0-9]+", "Vue component attribute"),
        (r"(?i)vue(?:\.global)?(?:\.min)?\.js", "Vue script reference"),
    ]),
    ("Nuxt", "Frontend Framework", [
        (r"(?i)__NUXT__", "Nuxt runtime marker"),
        (r"(?i)/_nuxt/", "Nuxt asset path"),
    ]),
    ("Svelte", "Frontend Framework", [
        (r"(?i)svelte-[a-z0-9]+", "Svelte component marker"),
        (r"(?i)/_app/immutable/", "SvelteKit asset path"),
    ]),
    ("jQuery", "JavaScript Library", [
        (r"(?i)jquery(?:-[\d.]+)?(?:\.min)?\.js", "jQuery script reference"),
    ]),
    ("Bootstrap", "CSS Framework", [
        (r"(?i)bootstrap(?:\.min)?\.css", "Bootstrap stylesheet"),
        (r"(?i)bootstrap(?:\.bundle)?(?:\.min)?\.js", "Bootstrap script"),
    ]),
    ("Tailwind CSS", "CSS Framework", [
        (r"(?i)tailwindcss", "Tailwind CSS reference"),
    ]),
    ("Vite", "Build Tool", [
        (r"(?i)/@vite/client", "Vite development client"),
    ]),
    ("Webpack", "Build Tool", [
        (r"(?i)webpackJsonp|webpackChunk", "Webpack runtime marker"),
    ]),

    # Backend frameworks
    ("Laravel", "Backend Framework", [
        (r"(?i)laravel_session", "Laravel session cookie"),
        (r"(?i)/vendor/laravel/", "Laravel asset reference"),
    ]),
    ("Django", "Backend Framework", [
        (r"(?i)csrftoken", "Django CSRF cookie indicator"),
        (r"(?i)django", "Django fingerprint"),
    ]),
    ("Flask", "Backend Framework", [
        (r"(?i)werkzeug", "Werkzeug fingerprint"),
        (r"(?i)flask", "Flask fingerprint"),
    ]),
    ("Express.js", "Backend Framework", [
        (r"(?i)x-powered-by:\s*express", "Express response header"),
    ]),
    ("Ruby on Rails", "Backend Framework", [
        (r"(?i)_rails_session", "Rails session cookie"),
    ]),
    ("Spring Boot", "Backend Framework", [
        (r"(?i)x-application-context", "Spring application header"),
    ]),

    # Web servers / proxy / hosting
    ("Nginx", "Web Server", [
        (r"(?i)server:\s*nginx", "Server response header"),
    ]),
    ("Apache", "Web Server", [
        (r"(?i)server:\s*apache", "Server response header"),
    ]),
    ("Microsoft IIS", "Web Server", [
        (r"(?i)server:\s*microsoft-iis", "Server response header"),
    ]),
    ("LiteSpeed", "Web Server", [
        (r"(?i)server:\s*litespeed", "Server response header"),
    ]),
    ("Caddy", "Web Server", [
        (r"(?i)server:\s*caddy", "Server response header"),
    ]),
    ("Cloudflare", "CDN / Security", [
        (r"(?i)server:\s*cloudflare", "Server response header"),
        (r"(?i)cf-ray:", "Cloudflare Ray header"),
        (r"(?i)__cf_bm", "Cloudflare cookie"),
    ]),
    ("Amazon CloudFront", "CDN", [
        (r"(?i)x-amz-cf-id:", "CloudFront response header"),
        (r"(?i)cloudfront", "CloudFront fingerprint"),
    ]),
    ("Vercel", "Hosting Platform", [
        (r"(?i)x-vercel-id:", "Vercel response header"),
    ]),
    ("Netlify", "Hosting Platform", [
        (r"(?i)server:\s*netlify", "Netlify response header"),
        (r"(?i)\.netlify\.app", "Netlify domain reference"),
    ]),

    # Analytics / monitoring
    ("Google Analytics", "Analytics", [
        (r"(?i)google-analytics\.com|googletagmanager\.com", "Google Analytics script"),
        (r"(?i)gtag\(", "Google tag JavaScript"),
    ]),
    ("Google Tag Manager", "Analytics", [
        (r"(?i)googletagmanager\.com/gtm\.js", "GTM script"),
    ]),
    ("Meta Pixel", "Analytics", [
        (r"(?i)connect\.facebook\.net/.*/fbevents\.js", "Meta Pixel script"),
    ]),
]



def extract_version(name, searchable):
    patterns = {
        "PHP": r"(?i)x-powered-by:\s*php/?([0-9][\w.-]*)",
        "Angular": r'(?i)ng-version=["\']([^"\']+)["\']',
        "jQuery": r"(?i)jquery[-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "Bootstrap": r"(?i)bootstrap(?:@|-)([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "Nginx": r"(?i)server:\s*nginx/([0-9.]+)",
        "Apache": r"(?i)server:\s*apache/([0-9.]+)",
        "Microsoft IIS": r"(?i)server:\s*microsoft-iis/([0-9.]+)",
        "LiteSpeed": r"(?i)server:\s*litespeed(?:/|\s+)([0-9.]+)",
        "Caddy": r"(?i)server:\s*caddy/([0-9.]+)",
    }

    pattern = patterns.get(name)
    if not pattern:
        return None

    match = re.search(pattern, searchable)
    return match.group(1) if match else None


def detect_technologies(headers, content) -> dict:
    """Identify publicly exposed technology fingerprints without extra requests."""
    header_text = "\n".join(
        f"{key}: {value}" for key, value in headers.items()
    )

    if isinstance(content, bytes):
        body = content.decode("utf-8", errors="replace")
    else:
        body = str(content or "")

    cookie_text = ""
    get_all = getattr(headers, "get_all", None)

    if callable(get_all):
        cookie_headers = get_all("Set-Cookie", [])
    else:
        cookie_value = next(
            (
                value for key, value in headers.items()
                if key.lower() == "set-cookie"
            ),
            [],
        )
        cookie_headers = (
            cookie_value if isinstance(cookie_value, (list, tuple))
            else [cookie_value] if cookie_value
            else []
        )

    for cookie_header in cookie_headers:
        cookie_text += "\n" + str(cookie_header)

    searchable = header_text + "\n" + cookie_text + "\n" + body
    found = {}

    for name, category, patterns in SIGNATURES:
        evidence = []

        for pattern, description in patterns:
            match = re.search(pattern, searchable)
            if match:
                evidence.append(description)

        if evidence:
            unique_evidence = list(dict.fromkeys(evidence))
            confidence = (
                "High" if len(unique_evidence) >= 2 else "Medium"
            )

            found[name] = {
                "name": name,
                "category": category,
                "version": extract_version(name, searchable),
                "confidence": confidence,
                "evidence": unique_evidence,
            }

    return {
        "technologies": sorted(
            found.values(),
            key=lambda item: (item["category"], item["name"].lower()),
        ),
        "total": len(found),
        "note": (
            "Detection is based on publicly exposed fingerprints. "
            "Undisclosed or hidden technologies cannot be confirmed."
        ),
    }

