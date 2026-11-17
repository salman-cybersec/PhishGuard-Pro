from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishguard.services import list_services

console = Console()


def show_banner():
    logo = Text(
        " ____  _     _ ____  _   _  __ _   ____  _   _  ____  ____  \n"
        "|  _ \\| |__ (_) ___|| | | |/ _| | |  _ \\| | | |/ ___|/ ___| \n"
        "| |_) | '_ \\| |\\___ \\| |_| | |_| | | |_) | | | |\\___ \\\\___ \\\n"
        "|  __/| | | | | ___) |  _  |  _| | |  __/| |_| | ___) |___) |\n"
        "|_|   |_| |_|_||____/|_| |_|_| |_| |_|    \\___/ |____/|____/ \n"
        "\n"
        "       ADVANCED SECURITY AWARENESS TOOLKIT\n"
        "       Developer: Salman Afzal\n"
        "       22 Supported Awareness Services\n",
        style="bold cyan",
    )

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
