import shutil
import subprocess
import sys
import time
from rich.console import Console
from rich.table import Table

console = Console()

def hr():
    console.rule()

def ok(msg): console.print(f"[bold green]✓[/bold green] {msg}")
def info(msg): console.print(f"[bold cyan]•[/bold cyan] {msg}")
def warn(msg): console.print(f"[bold yellow]![/bold yellow] {msg}")
def err(msg): console.print(f"[bold red]✗ {msg}[/bold red]")

def spinner(task, func, *args, **kwargs):
    with console.status(f"[bold green]{task}...", spinner="dots"):
        return func(*args, **kwargs)

def make_table(title, cols):
    table = Table(title=title, title_style="bold magenta", show_header=True, header_style="bold white")
    for c in cols:
        table.add_column(c)
    return table

def have_cmd(cmd):
    return shutil.which(cmd) is not None

def run_cmd(args, timeout=15):
    try:
        out = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout, text=True)
        return out
    except Exception as e:
        return ""
