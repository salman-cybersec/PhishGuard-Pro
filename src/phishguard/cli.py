
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table

from phishguard.banner import show_banner
from phishguard.database import initialize_database
from phishguard.campaigns import create_campaign, list_campaigns
from phishguard.campaign_controls import update_campaign_status
from phishguard.analytics import get_campaign_analytics


console = Console()


def show_menu():
    console.print(
        Panel(
            "[bold cyan]1.[/bold cyan] Campaign Management\n"
            "[bold cyan]2.[/bold cyan] Simulation Analytics\n"
            "[bold cyan]3.[/bold cyan] Security Testing\n"
            "[bold cyan]4.[/bold cyan] Generate Reports\n"
            "[bold cyan]5.[/bold cyan] Project Information\n"
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


def main():
    initialize_database()
    show_banner()

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
            console.print(
                "[cyan]PhishGuard Pro - Authorized Security Lab Toolkit[/cyan]"
            )
            console.print("[white]Developer: Salman Afzal[/white]")

        elif choice in {"3", "4"}:
            console.print(
                "[yellow]This module will be integrated in a future step.[/yellow]"
            )

        else:
            console.print("[red]Invalid option. Try again.[/red]")


if __name__ == "__main__":
    main()
