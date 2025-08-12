# modules/ssl_inspector.py
import socket
import ssl
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.utils import clear_console

console = Console()

# --- Helper function to export results ---
def export_results(results: Dict[str, Any], host: str):
    """Asks the user if they want to export the results and saves them."""
    while True:
        choice = console.input("\n[bold]Export results? (json/txt/no): [/]").strip().lower()
        if choice in ['json', 'txt', 'no']:
            break
        console.print("[yellow]Invalid choice. Please enter 'json', 'txt', or 'no'.[/yellow]")

    if choice == 'no':
        return

    filename = f"{host.replace('.', '_')}_ssl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{choice}"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if choice == 'json':
                class CustomEncoder(json.JSONEncoder):
                    def default(self, o):
                        if isinstance(o, datetime):
                            return o.isoformat()
                        if isinstance(o, x509.Certificate):
                            try:
                                return o.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                            except (x509.ExtensionNotFound, IndexError):
                                return o.subject.rfc4514_string()
                        return super().default(o)
                json.dump(results, f, indent=4, cls=CustomEncoder)
            elif choice == 'txt':
                for key, value in results.items():
                    f.write(f"--- {key.replace('_', ' ').upper()} ---\n")
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            f.write(f"{sub_key.replace('_', ' ').capitalize()}: {sub_value}\n")
                    elif isinstance(value, list):
                        for item in value:
                            f.write(f"- {item}\n")
                    else:
                        f.write(f"{value}\n")
                    f.write("\n")
        console.print(f"[green]✔ Results successfully exported to [bold]{filename}[/bold][/green]")
    except IOError as e:
        console.print(f"[red]Error exporting results: {e}[/red]")


# --- TLS Score Calculation ---
def calculate_tls_score(results: Dict[str, Any]) -> Tuple[str, int]:
    """Calculates the TLS score based on various security metrics."""
    score = 100
    grade = "A+"

    protocols = results['protocols']
    if not protocols.get('TLSv1.3', False):
        score -= 5
    if not protocols.get('TLSv1.2', False):
        score -= 20
    if protocols.get('TLSv1.1', False):
        score -= 20
    if protocols.get('TLSv1.0', False):
        score -= 30
    if protocols.get('SSLv3', False): # Although not checked, still a penalty if present
        score -= 40

    if results['cipher_analysis']['strength'] == 'Weak':
        score -= 30
    elif results['cipher_analysis']['strength'] == 'Moderate':
        score -= 10
    
    key_size = results['certificate_details']['key_size']
    if isinstance(key_size, int) and key_size < 2048:
        score -= 20

    if results['validity']['is_expired'] or results['validity']['is_not_yet_valid']:
        score = 0
    elif 0 < results['validity']['days_remaining'] <= 14:
        score -= 10

    if results['certificate_details'].get('is_self_signed', False):
        score -= 50

    if not results['chain_details'].get('is_chain_complete', True):
        score -= 20

    if score >= 95: grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 65: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 35: grade = "D"
    else: grade = "F"
    
    if results['validity']['is_expired'] or results['validity']['is_not_yet_valid']:
        grade = "F"
        
    score = max(0, score)
    return grade, score


def resolve_host(host: str) -> Optional[str]:
    """Resolves a hostname to an IP address with error handling."""
    try:
        with console.status("[bold green]Resolving DNS...[/]", spinner="earth"):
            return socket.gethostbyname(host)
    except socket.gaierror as e:
        console.print(f"[bold red]DNS Resolution Error: {str(e)}[/bold red]")
        return None
    except Exception as e:
        console.print(f"[bold red]Unexpected DNS Error: {str(e)}[/bold red]")
        return None

def get_certificate_details(cert: x509.Certificate) -> Dict:
    """Parses X.509 certificate details using cryptography."""
    details = {
        'subject': {attr.oid._name: attr.value for attr in cert.subject},
        'issuer': {attr.oid._name: attr.value for attr in cert.issuer},
        'sans': [],
        'key_size': 'Unknown',
        'sig_algorithm': cert.signature_algorithm_oid._name,
        'is_self_signed': cert.issuer == cert.subject
    }
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        details['sans'] = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    pub_key = cert.public_key()
    if isinstance(pub_key, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        details['key_size'] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        details['key_size'] = pub_key.curve.key_size
    return details

def check_protocol_support(host: str, port: int) -> Dict[str, bool]:
    """Explicitly checks each major SSL/TLS protocol version."""
    supported_protocols = {
        'TLSv1.3': False, 'TLSv1.2': False, 'TLSv1.1': False, 'TLSv1.0': False
    }
    protocols_to_test = [
        ('TLSv1.3', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1_3}),
        ('TLSv1.2', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1_2, 'maximum_version': ssl.TLSVersion.TLSv1_2}),
        ('TLSv1.1', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1_1, 'maximum_version': ssl.TLSVersion.TLSv1_1}),
        ('TLSv1.0', ssl.PROTOCOL_TLS_CLIENT, {'minimum_version': ssl.TLSVersion.TLSv1, 'maximum_version': ssl.TLSVersion.TLSv1}),
    ]

    console.print("[cyan]Checking supported protocols...[/cyan]")
    for name, protocol_version, version_config in protocols_to_test:
        ctx = ssl.SSLContext(protocol_version)
        ctx.minimum_version = version_config.get('minimum_version', ssl.TLSVersion.SSLv3)
        ctx.maximum_version = version_config.get('maximum_version', ssl.TLSVersion.TLSv1_3)
        try:
            with socket.create_connection((host, port), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    supported_protocols[name] = True
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            supported_protocols[name] = False
        except Exception:
            supported_protocols[name] = False
            
    return supported_protocols


def analyze_cipher(cipher: Tuple) -> Dict:
    """Analyzes cipher strength and vulnerabilities."""
    name, _, bits = cipher
    analysis = {'strength': 'Strong', 'color': 'green', 'details': []}
    
    if bits is not None and bits < 128:
        analysis.update({'strength': 'Weak', 'color': 'red'})
    elif bits is not None and 128 <= bits < 256:
        analysis.update({'strength': 'Moderate', 'color': 'yellow'})
    
    weak_patterns = ['RC4', '3DES', 'MD5', 'CBC', 'EXPORT', 'NULL']
    for pattern in weak_patterns:
        if pattern in name.upper():
            analysis['details'].append(f"Contains weak element: {pattern}")
            analysis['color'] = 'red'
            analysis['strength'] = 'Weak'
    
    if 'GCM' in name or 'CHACHA20' in name:
        analysis['details'].append("Uses modern AEAD encryption")
    
    return analysis

def check_certificate_chain(host: str, port: int) -> Dict:
    """Fetches and analyzes the full certificate chain from the server."""
    chain_details = {'chain': [], 'is_chain_complete': False, 'chain_length': 0, 'error': None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_certs = ssock.get_verified_chain()
                if not der_certs:
                    der_certs_binary = ssock.getpeercert(binary_form=True)
                    if der_certs_binary:
                         der_certs = [x509.load_der_x509_certificate(der_certs_binary)]
                    else:
                        raise ConnectionError("Could not retrieve certificate chain.")

                pem_certs = [ssl.DER_cert_to_PEM_cert(der.public_bytes(default_backend())) for der in der_certs]
        
        chain = [x509.load_pem_x509_certificate(c.encode(), default_backend()) for c in pem_certs]
        chain_details['chain'] = chain
        chain_details['chain_length'] = len(chain)

        if not chain:
            chain_details['error'] = "No certificate chain received from server."
            chain_details['is_chain_complete'] = False
            return chain_details

        is_ordered = all(chain[i].issuer == chain[i+1].subject for i in range(len(chain) - 1))
        last_cert_is_root = chain[-1].issuer == chain[-1].subject
        
        if is_ordered and last_cert_is_root:
            chain_details['is_chain_complete'] = True

    except Exception as e:
        chain_details['error'] = str(e)
        chain_details['is_chain_complete'] = False
        chain_details['chain_length'] = len(chain_details.get('chain', []))
        
    return chain_details

def run_ssl_inspector():
    clear_console()
    console.print(Panel.fit("[b]🔒 SSL/TLS Inspector[/b] v3.2 (Refactored)", 
                          style="bold #00a8ff", border_style="#00a8ff", padding=(1,2)))
    
    while True:
        target = console.input("\n[bold]➤ Enter target (e.g., google.com): [/]").strip()
        if not target: continue
            
        host, port_str = (target.split(':', 1) + ['443'])[:2]
        try: port = int(port_str)
        except ValueError: console.print(f"[red]Invalid port: {port_str}[/red]"); continue
        
        ip = resolve_host(host)
        if not ip: continue
            
        scan_results = {}
        connection_success = False
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=10) as sock:
                    with console.status(f"[green]Performing SSL handshake (Attempt {attempt + 1}/{max_retries})...[/]", spinner="bouncingBall"):
                        s = ctx.wrap_socket(sock, server_hostname=host)
                    
                    console.print("[green]✔ Handshake successful.[/green]")
                    cert_der = s.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    scan_results['host_info'] = {'host': host, 'port': port, 'ip': ip}
                    scan_results['certificate_details'] = get_certificate_details(cert)
                    scan_results['protocols'] = check_protocol_support(host, port)
                    scan_results['cipher'] = s.cipher()
                    scan_results['cipher_analysis'] = analyze_cipher(s.cipher())
                    scan_results['chain_details'] = check_certificate_chain(host, port)
                    
                    now = datetime.now(datetime.now().astimezone().tzinfo)
                    scan_results['validity'] = {
                        'not_valid_after': cert.not_valid_after_utc,
                        'not_valid_before': cert.not_valid_before_utc,
                        'days_remaining': (cert.not_valid_after_utc - now).days,
                        'is_expired': now > cert.not_valid_after_utc,
                        'is_not_yet_valid': now < cert.not_valid_before_utc
                    }
                    
                    grade, score = calculate_tls_score(scan_results)
                    scan_results['tls_score'] = {'grade': grade, 'score': score}
                    connection_success = True
                    break

            except socket.timeout:
                console.print(f"[yellow]Connection timed out on attempt {attempt + 1}. Retrying...[/yellow]")
                time.sleep(1)
            except Exception as e:
                console.print(f"[bold red]An error occurred: {type(e).__name__} - {e}[/bold red]")
                break

        if not connection_success:
            console.print("[bold red]❌ Failed to connect to server after all attempts.[/bold red]")
        else:
            # --- Building and Printing Output ---
            console.rule(f"[bold]Scan Report for {host}:{port}[/bold]", style="#00a8ff")
            
            grade, score = scan_results['tls_score']['grade'], scan_results['tls_score']['score']
            score_color = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}.get(grade, "red")
            console.print(Panel(f"[{score_color} bold]{grade}[/]\nScore: {score}/100", title="[bold]Overall Rating[/]", style=score_color, width=25))

            cert_details = scan_results['certificate_details']
            cert_info = (f"[bold]Common Name:[/] {cert_details['subject'].get('commonName', 'N/A')}\n"
                         f"[bold]SANs:[/] {', '.join(cert_details['sans'][:3])}{'...' if len(cert_details['sans']) > 3 else ''}\n"
                         f"[bold]Issuer:[/] {cert_details['issuer'].get('organizationName', 'N/A')}\n")
            if cert_details['is_self_signed']: cert_info += "[bold red]⚠️ Self-Signed Certificate[/bold red]\n"
            console.print(Panel(cert_info, title="[bold #00a8ff]Certificate[/]", expand=False))

            details_table = Table(show_header=False, box=None, padding=(0, 1))
            details_table.add_column(style="bold #00a8ff"); details_table.add_column()

            validity = scan_results['validity']
            v_style = "green" if validity['days_remaining'] > 30 else "yellow" if validity['days_remaining'] > 0 else "red"
            v_text = f"[{v_style}]Expires in {validity['days_remaining']} days ({validity['not_valid_after']:%Y-%m-%d})[/{v_style}]"
            if validity['is_expired']: v_text = "[bold red]❌ Certificate has expired![/bold red]"
            if validity['is_not_yet_valid']: v_text = f"[bold red]⚠️ Not yet valid until {validity['not_valid_before']:%Y-%m-%d}[/bold red]"
            details_table.add_row("Validity", v_text)

            protocols = scan_results['protocols']
            proto_status = ' '.join([f"[{'green' if sup else 'red'}]{p.replace('TLSv', '1.')}[/]" for p, sup in protocols.items()])
            details_table.add_row("Protocols", proto_status)

            c_analysis = scan_results['cipher_analysis']
            c_text = f"[{c_analysis['color']}]{scan_results['cipher'][0]} ({scan_results['cipher'][2]} bits)[/{c_analysis['color']}]"
            details_table.add_row("Cipher Suite", c_text)

            chain = scan_results['chain_details']
            chain_color = "green" if chain['is_chain_complete'] else "yellow"
            chain_text = f"[{chain_color}]{chain['chain_length']} certificates found. Complete: {chain['is_chain_complete']}[/{chain_color}]"
            if chain['error']: chain_text += f"\n[dim yellow]({chain['error']})[/dim yellow]"
            details_table.add_row("Certificate Chain", chain_text)

            console.print(Panel(details_table, title="[bold #00a8ff]Security Details[/]", expand=False))
            
            export_results(scan_results, host)
        
        if console.input("\n[bold]Scan another target? (y/n): [/]").strip().lower() != 'y':
            break

if __name__ == "__main__":
    run_ssl_inspector()
