from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

from phishguard.banner import show_banner

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


def main():
    show_banner()

    while True:
        show_menu()
        choice = Prompt.ask(
            "[bold green]Select an option[/bold green]"
        )

        if choice == "0":
            console.print("[yellow]Exiting PhishGuard Pro.[/yellow]")
            break

        elif choice == "5":
            console.print(
                "[cyan]PhishGuard Pro - Authorized Security Lab Toolkit[/cyan]"
            )

        elif choice in {"1", "2", "3", "4"}:
            console.print(
                "[yellow]This module is planned for a future release.[/yellow]"
            )

        else:
            console.print("[red]Invalid option. Try again.[/red]")


if __name__ == "__main__":
    main()
