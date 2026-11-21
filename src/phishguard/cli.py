
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table
from threading import Thread
import time

import uvicorn

from phishguard.config import APP_HOST, APP_PORT
from phishguard.server import app

from phishguard.banner import show_banner, show_service_catalog
from phishguard.database import initialize_database
from phishguard.campaigns import create_campaign, list_campaigns
from phishguard.campaign_controls import update_campaign_status
from phishguard.analytics import get_campaign_analytics
from phishguard.website_authorization import (
    validate_website_authorization,
)
from phishguard.website_manager import import_website
from phishguard.config import build_preview_url
from phishguard.security_analyzer import analyze_website
from phishguard.full_scan import analyze_full_website
from phishguard.security_scan_store import save_security_scan
from phishguard.security_report import export_security_html_report, export_security_json_report


console = Console()


def show_menu():
    console.print(
        Panel(
            "[bold cyan]1.[/bold cyan] Campaign Management\n"
            "[bold cyan]2.[/bold cyan] Simulation Analytics\n"
            "[bold cyan]3.[/bold cyan] Security Testing\n"
            "[bold cyan]4.[/bold cyan] Generate Reports\n"
            "[bold cyan]5.[/bold cyan] Project Information\n"
            "[bold cyan]6.[/bold cyan] Website Import & Preview\n"
            "[bold red]0.[/bold red] Exit",
            title="[bold white]MAIN MENU[/bold white]",
            border_style="bright_blue",
        )
    )


def campaign_menu():
    while True:
        console.print(
            Panel(
                "[bold cyan]1.[/bold cyan] Create Campaign\n"
                "[bold cyan]2.[/bold cyan] List Campaigns\n"
                "[bold cyan]3.[/bold cyan] Update Campaign Status\n"
                "[bold red]0.[/bold red] Back",
                title="[bold white]CAMPAIGN MANAGEMENT[/bold white]",
                border_style="bright_blue",
            )
        )

        choice = Prompt.ask("Select an option")

        try:
            if choice == "1":
                name = Prompt.ask("Enter campaign name")
                campaign = create_campaign(name)

                console.print(
                    f"[green]Campaign created successfully.[/green]\n"
                    f"ID: {campaign['id']}\n"
                    f"Name: {campaign['name']}\n"
                    f"Status: {campaign['status']}"
                )

            elif choice == "2":
                campaigns = list_campaigns()

                if not campaigns:
                    console.print("[yellow]No campaigns found.[/yellow]")
                    continue

                table = Table(title="Campaign List")
                table.add_column("ID")
                table.add_column("Name")
                table.add_column("Status")
                table.add_column("Created At")

                for campaign in campaigns:
                    table.add_row(
                        str(campaign["id"]),
                        campaign["name"],
                        campaign["status"],
                        campaign["created_at"],
                    )

                console.print(table)

            elif choice == "3":
                campaign_id = Prompt.ask("Enter campaign ID")
                status = Prompt.ask(
                    "New status",
                    choices=["active", "paused", "completed"],
                )

                result = update_campaign_status(
                    int(campaign_id),
                    status,
                )

                console.print(
                    f"[green]Campaign status updated: "
                    f"{result['previous_status']} → {result['status']}[/green]"
                )

            elif choice == "0":
                break

            else:
                console.print("[red]Invalid option.[/red]")

        except ValueError as error:
            console.print(f"[red]Error: {error}[/red]")
        except RuntimeError as error:
            console.print(f"[red]Application error: {error}[/red]")


def analytics_menu():
    campaign_id = Prompt.ask("Enter campaign ID")

    try:
        analytics = get_campaign_analytics(int(campaign_id))
        campaign = analytics["campaign"]

        table = Table(title="Simulation Analytics")
        table.add_column("Metric", style="cyan")
        table.add_column("Result", style="green")

        table.add_row("Campaign", campaign["name"])
        table.add_row("Campaign Status", campaign["status"])
        table.add_row("Total Events", str(analytics["total_events"]))
        table.add_row("Page Visits", str(analytics["page_visits"]))
        table.add_row(
            "Training Page Views",
            str(analytics["training_page_views"]),
        )
        table.add_row(
            "Form Interactions",
            str(analytics["form_interactions"]),
        )
        table.add_row("Completions", str(analytics["completions"]))
        table.add_row(
            "Completion Rate",
            f"{analytics['completion_rate']}%",
        )

        console.print(table)

    except ValueError as error:
        console.print(f"[red]Error: {error}[/red]")
    except RuntimeError as error:
        console.print(f"[red]Application error: {error}[/red]")


def security_testing_menu():
    while True:
        console.print(
            Panel(
                "[bold cyan]1.[/bold cyan] Analyze HTTPS Website\n"
                "[bold cyan]2.[/bold cyan] Analyzer Information\n"
                "[bold cyan]3.[/bold cyan] Full Security Scan\n"
                "[bold red]0.[/bold red] Back",
                title="[bold white]SECURITY TESTING[/bold white]",
                border_style="bright_blue",
            )
        )

        choice = Prompt.ask("Select an option")

        if choice == "0":
            break

        elif choice == "2":
            console.print("[cyan]Website Security Analyzer[/cyan]")
            console.print("Checks HTTPS TLS certificate and security headers.")
            console.print("Resolves the hostname and blocks non-public IPs.")
            console.print("Does not exploit vulnerabilities or follow redirects.")
            console.print("Use only websites you own or are authorized to test.")

        elif choice == "1":
            url = Prompt.ask("Enter authorized HTTPS website URL")

            try:
                result = analyze_website(url)

                table = Table(title="Website Security Analysis")
                table.add_column("Metric", style="cyan")
                table.add_column("Result")

                table.add_row("Hostname", result["hostname"])
                table.add_row("HTTP Status", str(result["http_status"]))
                table.add_row("Resolved IPs", ", ".join(result["resolved_ips"]))
                table.add_row("TLS Version", str(result["tls"]["version"]))
                table.add_row("Certificate Expiry", str(result["tls"]["expires_at"]))
                table.add_row("Days Remaining", str(result["tls"]["days_remaining"]))
                table.add_row("Security Headers Present", ", ".join(result["headers"]["present"]) or "None")
                table.add_row("Security Headers Missing", ", ".join(result["headers"]["missing"]) or "None")
                table.add_row("Risk Level", result["risk_level"].upper())
                table.add_row("Security Score", f"{result['security_score']['score']}/100")
                table.add_row("Security Grade", result["security_score"]["grade"])
                table.add_row("Critical Findings", str(result["security_score"]["breakdown"]["critical"]))
                table.add_row("High Findings", str(result["security_score"]["breakdown"]["high"]))
                table.add_row("Medium Findings", str(result["security_score"]["breakdown"]["medium"]))
                table.add_row("Low Findings", str(result["security_score"]["breakdown"]["low"]))
                table.add_row("Total Findings", str(result["summary"]["total"]))

                console.print(table)

                if result["findings"]:
                    findings_table = Table(title="Security Findings")
                    findings_table.add_column("Severity")
                    findings_table.add_column("Finding")
                    findings_table.add_column("Recommended Fix")

                    for finding in result["findings"]:
                        findings_table.add_row(
                            finding["severity"].upper(),
                            finding["finding"],
                            finding.get(
                                "remediation",
                                "Review and apply an appropriate security fix.",
                            ),
                        )

                    console.print(findings_table)
                else:
                    console.print("[green]No findings detected by these checks.[/green]")

                save_report = Prompt.ask(
                    "Export HTML security report?",
                    choices=["y", "n"],
                    default="n",
                )

                html_report_path = None
                json_report_path = None

                if save_report == "y":
                    html_report = export_security_html_report(result)
                    html_report_path = html_report["html_report"]
                    console.print(
                        f"[green]HTML report saved:[/green] "
                        f"{html_report_path}"
                    )

                save_json = Prompt.ask(
                    "Export JSON security report?",
                    choices=["y", "n"],
                    default="n",
                )

                if save_json == "y":
                    json_report = export_security_json_report(result)
                    json_report_path = json_report["json_report"]
                    console.print(
                        f"[green]JSON report saved:[/green] "
                        f"{json_report_path}"
                    )

                scan_id = save_security_scan(
                    result,
                    html_report_path=html_report_path,
                    json_report_path=json_report_path,
                )
                console.print(
                    f"[green]Scan history saved. Scan ID: {scan_id}[/green]"
                )

            except (ValueError, RuntimeError, OSError) as error:
                console.print(f"[red]Analysis failed: {error}[/red]")

        elif choice == "3":
            url = Prompt.ask("Enter authorized HTTPS website URL")

            scan_mode = Prompt.ask(
                "Select scan depth",
                choices=["fast", "extended", "thorough"],
                default="fast",
            )

            try:
                result = analyze_full_website(url, scan_mode=scan_mode)
                score = result["security_score"]
                summary = result["summary"]
                subdomains = result["checks"].get("subdomains", {})

                table = Table(title="Full Website Security Scan")
                table.add_column("Metric", style="cyan")
                table.add_column("Result")

                table.add_row("Hostname", result["hostname"])
                table.add_row("Scan Mode", scan_mode.title())
                table.add_row("Risk Level", result["risk_level"].upper())
                table.add_row("Security Score", f"{score['score']}/100")
                table.add_row("Security Grade", score["grade"])
                table.add_row("Critical Findings", str(summary.get("critical", 0)))
                table.add_row("High Findings", str(summary.get("high", 0)))
                table.add_row("Medium Findings", str(summary.get("medium", 0)))
                table.add_row("Low Findings", str(summary.get("low", 0)))
                table.add_row("Total Findings", str(summary.get("total", 0)))
                table.add_row("Subdomains Discovered", str(subdomains.get("total_discovered", 0)))
                table.add_row("Subdomains Processed", str(subdomains.get("total_processed", 0)))
                table.add_row("Subdomains Resolved", str(subdomains.get("total_resolved", 0)))
                table.add_row("Subdomains Unresolved", str(subdomains.get("total_unresolved", 0)))
                table.add_row("Subdomain Results Truncated", str(subdomains.get("truncated", False)))

                console.print(table)

                if result["findings"]:
                    findings_table = Table(title="Full Scan Findings")
                    findings_table.add_column("Severity")
                    findings_table.add_column("Finding")
                    findings_table.add_column("Recommended Fix")

                    for finding in result["findings"]:
                        findings_table.add_row(
                            str(finding.get("severity", "")).upper(),
                            str(finding.get("finding", "")),
                            str(finding.get("remediation", "Review finding.")),
                        )

                    console.print(findings_table)
                else:
                    console.print("[green]No findings detected by these checks.[/green]")

                html_report_path = None
                json_report_path = None

                if Prompt.ask(
                    "Export HTML security report?",
                    choices=["y", "n"],
                    default="n",
                ) == "y":
                    report = export_security_html_report(result)
                    html_report_path = report["html_report"]
                    console.print(f"[green]HTML report saved:[/green] {html_report_path}")

                if Prompt.ask(
                    "Export JSON security report?",
                    choices=["y", "n"],
                    default="n",
                ) == "y":
                    report = export_security_json_report(result)
                    json_report_path = report["json_report"]
                    console.print(f"[green]JSON report saved:[/green] {json_report_path}")

                scan_id = save_security_scan(
                    result,
                    html_report_path=html_report_path,
                    json_report_path=json_report_path,
                )
                console.print(
                    f"[green]Full Scan history saved. Scan ID: {scan_id}[/green]"
                )

            except (ValueError, RuntimeError, OSError) as error:
                console.print(f"[red]Full Scan failed: {error}[/red]")

        else:
            console.print("[red]Invalid option. Try again.[/red]")


def website_import_menu():
    while True:
        console.print(
            Panel(
                "[bold cyan]1.[/bold cyan] Import Authorized Website\n"
                "[bold cyan]2.[/bold cyan] Website Import Information\n"
                "[bold red]0.[/bold red] Back",
                title="[bold white]WEBSITE IMPORT & PREVIEW[/bold white]",
                border_style="bright_blue",
            )
        )

        choice = Prompt.ask("Select an option")

        if choice == "0":
            break

        elif choice == "2":
            console.print(
                "[cyan]Website Import Security Information[/cyan]"
            )
            console.print(
                "Only HTTPS websites explicitly configured in "
                "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS can be imported."
            )
            console.print("Imported JavaScript is never executed.")
            console.print("HTML and CSS are sanitized before local preview.")
            console.print(
                "Real passwords and authentication credentials "
                "are not collected."
            )
            console.print("Only authorized websites should be used.")

        elif choice == "1":
            try:
                url = Prompt.ask(
                    "Enter your authorized website HTTPS URL"
                )

                authorization = validate_website_authorization(url)

                if not authorization["authorized"]:
                    console.print(
                        "[red]Website authorization failed.[/red]"
                    )
                    continue

                console.print(
                    "[green]Website domain authorization approved.[/green]"
                )

                result = import_website(url)
                preview_url = build_preview_url(
                    result["preview_id"]
                )

                table = Table(title="Website Import Result")
                table.add_column("Metric", style="cyan")
                table.add_column("Result", style="green")

                table.add_row("Website", result["website"])
                table.add_row("Status", result["status"])
                table.add_row("Preview ID", result["preview_id"])
                table.add_row("Preview Type", result["preview_type"])
                table.add_row(
                    "Assets Found",
                    str(result["assets_found"]),
                )
                table.add_row(
                    "Assets Imported",
                    str(result["assets_imported"]),
                )
                table.add_row(
                    "Assets Skipped",
                    str(result["assets_skipped"]),
                )
                table.add_row(
                    "Images Connected",
                    str(result["images_connected"]),
                )
                table.add_row(
                    "Stylesheets Connected",
                    str(result["stylesheets_connected"]),
                )
                table.add_row(
                    "JavaScript Executed",
                    str(result["javascript_executed"]),
                )
                table.add_row(
                    "Credentials Collected",
                    str(result["credentials_collected"]),
                )

                console.print(table)

                console.print(
                    "[green]Sanitized website preview saved successfully.[/green]"
                )
                console.print(
                    f"[bold cyan]Local Preview URL:[/bold cyan] {preview_url}"
                )
                console.print(
                    "[yellow]The local PhishGuard server must be running "
                    "before opening this URL.[/yellow]"
                )

            except ValueError as error:
                console.print(
                    f"[red]Validation error: {error}[/red]"
                )
            except RuntimeError as error:
                console.print(
                    f"[red]Import error: {error}[/red]"
                )

        else:
            console.print("[red]Invalid option.[/red]")


def start_backend():
    """Run the FastAPI backend in a managed background thread."""
    config = uvicorn.Config(
        app, host=APP_HOST, port=APP_PORT,
        log_level="warning", access_log=False,
    )
    server = uvicorn.Server(config)
    thread = Thread(target=server.run, name="phishguard-api", daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if server.started:
            console.print(f"[green]Backend running: http://{APP_HOST}:{APP_PORT}[/green]")
            console.print(f"[cyan]Admin dashboard: http://{APP_HOST}:{APP_PORT}/admin/login[/cyan]")
            return server, thread
        if not thread.is_alive():
            raise RuntimeError(
                f"Backend stopped during startup. Check whether port {APP_PORT} is in use."
            )
        time.sleep(0.1)

    server.should_exit = True
    thread.join(timeout=3)
    raise RuntimeError("Backend startup timed out.")


def stop_backend(server, thread):
    """Request a graceful backend shutdown."""
    server.should_exit = True
    thread.join(timeout=10)
    if thread.is_alive():
        console.print("[yellow]Backend is still shutting down; check the process.[/yellow]")
    else:
        console.print("[dim]Backend stopped.[/dim]")


def main():
    initialize_database()
    show_banner()
    show_service_catalog()
    server = None
    thread = None

    try:
        server, thread = start_backend()
        while True:
            show_menu()
            choice = Prompt.ask("Select an option")
            if choice == "0":
                console.print("[yellow]Exiting PhishGuard Pro.[/yellow]")
                break
            elif choice == "1":
                campaign_menu()
            elif choice == "2":
                analytics_menu()
            elif choice == "5":
                console.print("[cyan]PhishGuard Pro - Authorized Security Lab Toolkit[/cyan]")
                console.print("[white]Developer: Salman Afzal[/white]")
                console.print(f"[white]Backend: http://{APP_HOST}:{APP_PORT}[/white]")
            elif choice == "6":
                website_import_menu()
            elif choice == "3":
                security_testing_menu()
            elif choice == "4":
                console.print("[yellow]Report generation module is not available yet.[/yellow]")
            else:
                console.print("[red]Invalid option. Try again.[/red]")
    except (RuntimeError, OSError) as error:
        console.print(f"[bold red]Startup error: {error}[/bold red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown requested.[/yellow]")
    finally:
        if server is not None and thread is not None:
            stop_backend(server, thread)


if __name__ == "__main__":
    main()
