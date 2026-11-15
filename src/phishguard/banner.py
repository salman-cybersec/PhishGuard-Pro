from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def show_banner():
    logo = Text()
    logo.append("  ____  _     _     _    ____ _   _  __ _   ____  ____  \n", style="bold cyan")
    logo.append(" |  _ \\| |__ (_)___| |__ / ___| | | |/ _| | |  _ \\/ ___| \n", style="bold cyan")
    logo.append(" | |_) | '_ \\| / __| '_ \\ |  _| | | | |_| | | |_) \\___ \\ \n", style="bold cyan")
    logo.append(" |  __/| | | | \\__ \\ | | | |_| | |_| |  _| | |  __/ ___) |\n", style="bold cyan")
    logo.append(" |_|   |_| |_|_|___/_| |_|\\____|\\___/|_| |_| |_|   |____/ \n", style="bold cyan")
    logo.append("\n        PRO  |  SECURITY AWARENESS & LAB TESTING\n", style="bold white")
    logo.append("        Developer: Salman Afzal\n", style="dim")

    console.print(
        Panel(
            logo,
            border_style="bright_blue",
            title="[bold white]PHISHGUARD PRO[/bold white]",
            subtitle="[dim]Authorized Lab Use Only[/dim]",
        )
    )
