from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard.services import list_services

console = Console()


def show_banner():
    logo = Text()
    logo.append("PHISHGUARD PRO\n", style="bold #FFB36B")
    logo.append("AUTHORIZED RED TEAM TOOLKIT\n", style="bold white")
    logo.append("Developer: Salman Afzal\n", style="white")
    logo.append(
        f"{len(list_services())} Supported Red Team Services",
        style="bold red",
    )

    console.print(
        Panel(
            logo,
            border_style="#FFB36B",
            title="[bold white]SECURITY TOOLKIT[/bold white]",
            subtitle="[dim white]Authorized Lab Use Only[/dim white]",
            padding=(1, 3),
        )
    )

def show_service_catalog():
    services = list_services()
    table = Table(
        title=f"RED TEAM SERVICE CATALOG ({len(services)})",
        border_style="bright_blue",
        show_lines=False,
    )
    table.add_column("#", style="bold cyan", justify="right")
    table.add_column("Service", style="bold red")
    table.add_column("Security Checks", style="white")

    for index, service in enumerate(services, start=1):
        scenarios = ", ".join(
            item.replace("_", " ").title()
            for item in service["scenarios"]
        )
        table.add_row(f"{index:02d}", service["name"], scenarios)

    console.print(table)
    console.print(
        "[dim]Authorized security assessments only — no real passwords or credentials are collected.[/dim]"
    )
