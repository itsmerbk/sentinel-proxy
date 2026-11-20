import json
import time

from rich.console import Console
from rich.live import Live
from rich.table import Table

from sentinel.database import get_recent_logs, get_summary_stats, init_db

console = Console()


def build_dashboard() -> Table:
    stats = get_summary_stats()
    logs = get_recent_logs(12)

    header = (
        f"[bold cyan]Total Inspected:[/bold cyan] {stats['total_inspected']}   "
        f"[bold green]Allowed:[/bold green] {stats['allowed']}   "
        f"[bold red]Blocked:[/bold red] {stats['blocked']}   "
        f"[bold yellow]Avg Latency:[/bold yellow] {stats['avg_latency_ms']} ms"
    )

    table = Table(
        title=f"SentinelProxy Live Firewall Telemetry\n{header}",
        expand=True,
        border_style="bright_blue",
    )
    table.add_column("ID", style="dim", width=5)
    table.add_column("Stage", style="cyan", width=15)
    table.add_column("Target", style="magenta", width=18)
    table.add_column("Decision", width=10)
    table.add_column("Risk", justify="right", width=6)
    table.add_column("Matched Rules", style="yellow", width=28)
    table.add_column("Payload Preview", style="white")

    for row in logs:
        is_blocked = row["decision"] == "BLOCK"
        badge = "[bold red]BLOCK[/bold red]" if is_blocked else "[bold green]ALLOW[/bold green]"
        rules = ", ".join(json.loads(row["matched_rules"])) or "—"
        table.add_row(
            str(row["id"]),
            row["stage"],
            row["target"],
            badge,
            str(row["risk_score"]),
            rules,
            row["payload_preview"],
        )

    return table


def main() -> None:
    init_db()
    with Live(build_dashboard(), refresh_per_second=2, console=console) as live:
        while True:
            time.sleep(0.5)
            live.update(build_dashboard())


if __name__ == "__main__":
    main()
