import nmap
import logging
from rich.console import Console
from rich.table import Table

def setup_logger(log_file):
    """Setup logger to write output to a log file."""
    logging.basicConfig(
        filename=log_file,
        filemode='w',
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )

def perform_nmap_scan(target, options, log_file):
    """Perform an Nmap scan, log the results, and display them in a table."""
    setup_logger(log_file)
    scanner = nmap.PortScanner()
    console = Console()
    
    logging.info(f"Starting Nmap scan on target: {target} with options: {options}")
    console.print(f"[bold cyan]Starting Nmap scan on target:[/bold cyan] {target} with options: {options}")
    
    try:
        scanner.scan(target, arguments=options)
        for host in scanner.all_hosts():
            host_name = scanner[host].hostname()
            state = scanner[host].state()
            
            logging.info(f"Host: {host} ({host_name})")
            logging.info(f"State: {state}")
            
            console.print(f"\n[bold green]Host:[/bold green] {host} ({host_name})")
            console.print(f"[bold yellow]State:[/bold yellow] {state}")
            
            for proto in scanner[host].all_protocols():
                table = Table(title=f"Protocol: {proto}")
                table.add_column("Port", style="bold magenta")
                table.add_column("State", style="bold red")
                table.add_column("Service", style="bold cyan")
                table.add_column("Version", style="bold blue")
                table.add_column("Extra Info", style="bold yellow")
                
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    port_data = scanner[host][proto][port]
                    status = port_data.get('state', 'Unknown')
                    service = port_data.get('name', 'Unknown')
                    version = port_data.get('version', 'Unknown')
                    extra_info = port_data.get('extrainfo', 'N/A')
                    
                    logging.info(f"Port: {port}, State: {status}, Service: {service}, Version: {version}, Extra Info: {extra_info}")
                    table.add_row(str(port), status, service, version, extra_info)
                
                console.print(table)
            
            if 'osmatch' in scanner[host]:
                console.print("\n[bold green]OS Detection:[/bold green]")
                for os in scanner[host]['osmatch']:
                    logging.info(f"OS: {os['name']}, Accuracy: {os['accuracy']}%")
                    console.print(f"OS: {os['name']} (Accuracy: {os['accuracy']}%)")
            
            if 'tcpsequence' in scanner[host]:
                console.print("\n[bold green]TCP Sequence Prediction:[/bold green]")
                logging.info(f"TCP Sequence: {scanner[host]['tcpsequence']}")
                console.print(scanner[host]['tcpsequence'])
            
            if 'uptime' in scanner[host]:
                console.print("\n[bold green]Uptime Information:[/bold green]")
                logging.info(f"Uptime: {scanner[host]['uptime']}")
                console.print(scanner[host]['uptime'])
            
            if 'hostscript' in scanner[host]:
                console.print("\n[bold green]Host Scripts:[/bold green]")
                for script in scanner[host]['hostscript']:
                    logging.info(f"Script: {script['id']}, Output: {script['output']}")
                    console.print(f"[bold cyan]{script['id']}:[/bold cyan] {script['output']}")
        
    except Exception as e:
        logging.error(f"Error during scan: {e}")
        console.print(f"[bold red]Error during scan:[/bold red] {e}")

if __name__ == "__main__":
    console = Console()
    console.print("[bold cyan]Select Scan Options:[/bold cyan]")
    console.print("  -O   : Check OS Version")
    console.print("  -sV  : Detect Service Versions")
    console.print("  -sS  : Perform Stealth Scan")
    console.print("  -sU  : Scan UDP Ports")
    console.print("  -p   : Scan Specific Ports (e.g., -p 80,443)")
    console.print("  -A   : Enable OS and Version Detection, Traceroute, and Scripts")
    console.print("  --script : Run Custom Nmap Scripts (e.g., --script http-title)")
    console.print("\n[bold yellow]Use space to add multiple options[/bold yellow]")
    
    target_ip = console.input("[bold cyan]Enter Target IP: [/bold cyan]")
    scan_options = console.input("[bold cyan]Enter Scan Options: [/bold cyan]")
    log_filename = "nmap_scan.log"
    
    perform_nmap_scan(target_ip, scan_options, log_filename)
    console.print(f"[bold green]Nmap scan completed. Results saved in {log_filename}[/bold green]")
