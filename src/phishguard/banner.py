from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard.services import list_services

console = Console()


def show_banner():
    logo = Text()
    logo.append("  ____  _     _     _    ____ _   _  __ _   ____  ____  \\n", style="bold cyan")
    logo.append(" |  _ \\| |__ (_)___| |__ / ___| | | |/ _| | |  _ \\/ ___| \\n", style="bold cyan")
    logo.append(" | |_) | '_ \\| / __| '_ \\ |  _| | | | |_| | | |_) \\___ \\ \\n", style="bold cyan")
    logo.append(" |  __/| | | | \\__ \\ | | | |_| | |_| |  _| | |  __/ ___) |\\n", style="bold cyan")
    logo.append(" |_|   |_| |_|_|___/_| |_|\\____|\\___/|_| |_| |_|   |____/ \\n", style="bold cyan")
    logo.append("\\n        PRO  |  ADVANCED SECURITY AWARENESS TOOLKIT\\n", style="bold white")
    logo.append("        Developer: Salman Afzal\\n", style="dim")
    logo.append("        22+ Security Awareness Service Scenarios\\n", style="bold green")

    console.print(
        Panel(
            logo,
            border_style="bright_blue",
            title="[bold white]PHISHGUARD PRO[/bold white]",
            subtitle="[dim]Authorized Lab Use Only[/dim]",
        )
    )


def show_service_catalog():
    services = list_services()
    table = Table(
        title=f"AVAILABLE TRAINING SERVICES ({len(services)})",
        border_style="bright_blue",
        show_lines=False,
    )
    table.add_column("#", style="bold cyan", justify="right")
    table.add_column("Service", style="white")
    table.add_column("Awareness Scenarios", style="green")

    for index, service in enumerate(services, start=1):
        scenarios = ", ".join(
            item.replace("_", " ").title()
            for item in service["scenarios"]
        )
        table.add_row(f"{index:02d}", service["name"], scenarios)

    console.print(table)
    console.print(
        "[dim]Training simulations only — no real passwords or credentials are collected.[/dim]"
    )
