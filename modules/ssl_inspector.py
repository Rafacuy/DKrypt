# modules/ssl_inspector.py
import socket
import ssl
import json
import time
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.utils import clear_console, header_banner

console = Console()

# --- Constants ---
PFS_KEY_EXCHANGES = {'ECDHE', 'DHE'}
AEAD_CIPHERS = {'GCM', 'CHACHA20', 'POLY1305'}
WEAK_ALGORITHMS = ['RC4', '3DES', 'MD5', 'CBC', 'EXPORT', 'NULL']
INSECURE_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']

# --- Helper function to export results ---
def export_results(results: Dict[str, Any], host: str, choice: str = None):
    """Asks the user if they want to export the results and saves them."""
    if not choice or choice == 'no':
        return

    export_dir = "reports/ssl_results"
    try:
        os.makedirs(export_dir, exist_ok=True)
    except OSError as e:
        console.print(f"[red]Error creating directory {export_dir}: {e}[/red]")
        return

    filename = f"{host.replace('.', '_')}_ssl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{choice}"
    filepath = os.path.join(export_dir, filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            if choice == 'json':
                class CustomEncoder(json.JSONEncoder):
                    def default(self, o):
                        if isinstance(o, datetime):
                            return o.isoformat()
                        if isinstance(o, x509.Certificate):
                            try:
                                return o.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                            except (IndexError, x509.ExtensionNotFound):
                                return o.subject.rfc4514_string()
                        return str(o)
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
        console.print(f"[green]✔ Results successfully exported to [bold]{filepath}[/bold][/green]")
    except IOError as e:
        console.print(f"[red]Error exporting results: {e}[/red]")


# --- TLS Score Calculation ---
def calculate_tls_score(results: Dict[str, Any]) -> Tuple[str, int]:
    """Calculates the TLS score based on a weighted security assessment."""
    scores = {
        'protocol': 100,
        'cipher': 100,
        'certificate': 100,
        'chain': 100
    }

    # 1. Protocol Score (30%)
    protocols = results.get('protocols', {})
    supported = protocols.get('supported', [])
    insecure = protocols.get('insecure', [])
    
    if 'TLSv1.3' not in supported:
        scores['protocol'] -= 10
    if 'TLSv1.2' not in supported:
        scores['protocol'] -= 30
    
    # Heavy penalties for insecure protocols
    for proto in insecure:
        if proto == 'SSLv2':
            scores['protocol'] -= 100
        elif proto == 'SSLv3':
            scores['protocol'] -= 80
        elif proto in ['TLSv1.0', 'TLSv1.1']:
            scores['protocol'] -= 40

    # 2. Cipher Score (25%)
    cipher_analysis = results.get('cipher_analysis', {})
    if cipher_analysis.get('strength') == 'Weak':
        scores['cipher'] -= 70
    elif cipher_analysis.get('strength') == 'Moderate':
        scores['cipher'] -= 20
    
    if not cipher_analysis.get('pfs', False):
        scores['cipher'] -= 25
    if not cipher_analysis.get('aead', False):
        scores['cipher'] -= 15

    # 3. Certificate Score (25%)
    cert_details = results.get('certificate_details', {})
    validity = results.get('validity', {})
    
    if validity.get('is_expired', False):
        scores['certificate'] = 0
    elif validity.get('is_not_yet_valid', False):
        scores['certificate'] -= 50
    
    if cert_details.get('key_size', 0) < 2048:
        scores['certificate'] -= 50
    elif cert_details.get('key_size', 0) < 4096:
        scores['certificate'] -= 10
    
    if 'sha1' in cert_details.get('sig_algorithm', '').lower():
        scores['certificate'] -= 80
    
    if cert_details.get('is_self_signed', False):
        scores['certificate'] -= 60

    # Certificate validity time penalties
    days_remaining = validity.get('days_remaining', 0)
    if 0 < days_remaining <= 7:
        scores['certificate'] -= 30
    elif 0 < days_remaining <= 30:
        scores['certificate'] -= 15

    # 4. Chain Score (20%)
    chain_details = results.get('chain_details', {})
    if not chain_details.get('is_chain_complete', True):
        scores['chain'] -= 50
    if not chain_details.get('is_trusted', True):
        scores['chain'] -= 80

    # Calculate final weighted score
    final_score = int(
        (max(0, scores['protocol']) * 0.30) +
        (max(0, scores['cipher']) * 0.25) +
        (max(0, scores['certificate']) * 0.25) +
        (max(0, scores['chain']) * 0.20)
    )

    # Determine grade
    if final_score >= 95:
        grade = "A+"
    elif final_score >= 85:
        grade = "A"
    elif final_score >= 75:
        grade = "B"
    elif final_score >= 65:
        grade = "C"
    elif final_score >= 50:
        grade = "D"
    else:
        grade = "F"
    
    # Automatic F for expired certificates or critical security issues
    if validity.get('is_expired', False) or 'SSLv2' in supported or 'SSLv3' in supported:
        grade = "F"

    return grade, final_score


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


def get_certificate_details(cert: x509.Certificate, is_trusted: bool = False) -> Dict:
    """Parses X.509 certificate details using cryptography."""
    details = {
        'subject': {},
        'issuer': {},
        'common_name': 'N/A',
        'sans': [],
        'key_size': 'Unknown',
        'sig_algorithm': cert.signature_algorithm_oid._name,
        'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(':').upper(),
        'is_self_signed': cert.issuer == cert.subject,
        'is_trusted': is_trusted,
        'weak_elements': []
    }

    # Extract subject and issuer attributes
    for attr in cert.subject:
        details['subject'][attr.oid._name] = attr.value
    for attr in cert.issuer:
        details['issuer'][attr.oid._name] = attr.value

    # Get common name
    try:
        details['common_name'] = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, x509.ExtensionNotFound):
        pass

    # Get SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        details['sans'] = [name for name in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    # Get key information
    pub_key = cert.public_key()
    if isinstance(pub_key, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        details['key_size'] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        details['key_size'] = pub_key.curve.key_size

    # Check for weak signature algorithm
    if 'sha1' in details['sig_algorithm'].lower():
        details['weak_elements'].append('SHA1 Signature')

    return details


def check_protocol_support(host: str, port: int) -> Dict[str, Any]:
    """Checks for supported SSL/TLS protocol versions."""
    protocols_to_test = [
        ('TLSv1.3', ssl.TLSVersion.TLSv1_3),
        ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
        ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
        ('TLSv1.0', ssl.TLSVersion.TLSv1),
    ]
    
    results = {
        'supported': [],
        'insecure': [],
        'min_supported': 'None',
        'max_supported': 'None'
    }

    console.print("[cyan]Testing protocol support...[/cyan]")
    
    for name, version in protocols_to_test:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    results['supported'].append(name)
                    if name in INSECURE_PROTOCOLS:
                        results['insecure'].append(name)
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            continue

    if results['supported']:
        results['min_supported'] = results['supported'][-1]  # Oldest supported
        results['max_supported'] = results['supported'][0]   # Newest supported

    return results


def analyze_cipher(cipher: Tuple) -> Dict:
    """Analyzes cipher details including strength, PFS, and AEAD."""
    name, version, bits = cipher
    
    analysis = {
        'name': name,
        'version': version,
        'bits': bits,
        'strength': 'Strong',
        'pfs': False,
        'aead': False,
        'weak_elements': []
    }

    # Check for Perfect Forward Secrecy
    analysis['pfs'] = any(pfs in name for pfs in PFS_KEY_EXCHANGES)
    
    # Check for AEAD (Authenticated Encryption with Associated Data)
    analysis['aead'] = any(aead in name for aead in AEAD_CIPHERS)

    # Determine cipher strength
    if bits and bits < 128:
        analysis['strength'] = 'Weak'
        analysis['weak_elements'].append(f"Key size < 128 bits ({bits} bits)")
    elif bits and 128 <= bits < 256:
        analysis['strength'] = 'Moderate'

    # Check for weak cipher components
    for weak in WEAK_ALGORITHMS:
        if weak in name.upper():
            analysis['strength'] = 'Weak'
            analysis['weak_elements'].append(f"Uses weak algorithm: {weak}")

    return analysis


def check_certificate_chain(host: str, port: int) -> Dict:
    """Analyzes the certificate chain for completeness and trust."""
    chain_details = {
        'is_chain_complete': False,
        'is_trusted': False,
        'chain_length': 0,
        'missing_intermediates': [],
        'error': None
    }

    try:
        # Test with default context (includes trust store verification)
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # If we reach here, the chain is trusted
                chain_details['is_trusted'] = True
                chain_details['is_chain_complete'] = True
                
                # Try to get chain length
                try:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        chain_details['chain_length'] = 1  # At least the server cert
                except:
                    pass

    except ssl.SSLCertVerificationError as e:
        chain_details['error'] = str(e)
        if "self-signed" in str(e).lower():
            chain_details['is_chain_complete'] = True  # Self-signed is "complete" but not trusted
        elif "unable to get local issuer" in str(e).lower():
            chain_details['missing_intermediates'].append("Missing intermediate certificate")
    except Exception as e:
        chain_details['error'] = str(e)

    return chain_details


def check_security_features(host: str, port: int) -> Dict:
    """Checks for additional security features."""
    features = {
        'secure_renegotiation': False,
        'compression_disabled': True,  # Assume disabled (secure default)
        'session_resumption': False
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Check compression (should be None for security)
                if ssock.compression():
                    features['compression_disabled'] = False
                
                # Basic session resumption test
                session = ssock.session
                if session:
                    try:
                        with socket.create_connection((host, port), timeout=3) as sock2:
                            with context.wrap_socket(sock2, server_hostname=host, session=session) as ssock2:
                                if ssock2.session_reused():
                                    features['session_resumption'] = True
                    except:
                        pass

    except Exception:
        pass

    return features


def run_ssl_inspector(args=None):
    """Main function to run the SSL/TLS inspection."""
    clear_console()
    header_banner(tool_name="SSL Inspector")

    if args:
        target = args.target
        export_format = args.export
        # Parse host and port
        host, port_str = (target.split(':', 1) + ['443'])[:2]
        try:
            port = int(port_str)
        except ValueError:
            console.print(f"[red]Invalid port: {port_str}[/red]")
            return
        
        # Resolve hostname
        ip = resolve_host(host)
        if not ip:
            return

        scan_results = {}
        connection_success = False

        # Attempt connection with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with console.status(f"[green]Connecting to {host}:{port} (Attempt {attempt + 1}/{max_retries})...[/]", spinner="bouncingBall"):
                    context = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            # Get certificate and cipher information
                            cert_der = ssock.getpeercert(binary_form=True)
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            cipher_info = ssock.cipher()

                console.print("[green]✔ Connection successful![/green]")

                # Perform comprehensive security analysis
                with console.status("[cyan]Analyzing security configuration...[/]", spinner="dots"):
                    chain_details = check_certificate_chain(host, port)
                    
                    scan_results = {
                        'host_info': {'host': host, 'ip': ip, 'port': port},
                        'protocols': check_protocol_support(host, port),
                        'cipher_analysis': analyze_cipher(cipher_info),
                        'certificate_details': get_certificate_details(cert, chain_details['is_trusted']),
                        'chain_details': chain_details,
                        'security_features': check_security_features(host, port)
                    }

                    # Certificate validity information
                    now = datetime.now(datetime.now().astimezone().tzinfo)
                    scan_results['validity'] = {
                        'not_valid_after': cert.not_valid_after_utc,
                        'not_valid_before': cert.not_valid_before_utc,
                        'days_remaining': (cert.not_valid_after_utc - now).days,
                        'is_expired': now > cert.not_valid_after_utc,
                        'is_not_yet_valid': now < cert.not_valid_before_utc
                    }

                    # Calculate security score
                    grade, score = calculate_tls_score(scan_results)
                    scan_results['tls_score'] = {'grade': grade, 'score': score}

                connection_success = True
                break

            except socket.timeout:
                console.print(f"[yellow]Connection timeout on attempt {attempt + 1}[/yellow]")
                if attempt < max_retries - 1:
                    time.sleep(1)
            except Exception as e:
                console.print(f"[red]Connection failed: {type(e).__name__} - {e}[/red]")
                if attempt < max_retries - 1:
                    time.sleep(1)
                break

        if not connection_success:
            console.print("[bold red]❌ Failed to establish secure connection after all attempts.[/bold red]")
            return

        # Display comprehensive results
        console.rule(f"[bold]Security Assessment for {host}:{port}[/bold]", style="#00a8ff")
        
        # Overall security grade
        grade, score = scan_results['tls_score']['grade'], scan_results['tls_score']['score']
        grade_colors = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
        grade_color = grade_colors.get(grade, "red")
        
        console.print(Panel(
            f"[{grade_color} bold]{grade}[/]\nScore: {score}/100",
            title="[bold]Security Grade[/]",
            style=grade_color,
            width=25
        ))

        # Certificate information
        cert_details = scan_results['certificate_details']
        cert_info = (
            f"[bold]Common Name:[/] {cert_details['common_name']}\n"
            f"[bold]Issuer:[/] {cert_details['issuer'].get('organizationName', 'N/A')}\n"
            f"[bold]Key Size:[/] {cert_details['key_size']} bits\n"
            f"[bold]Signature:[/] {cert_details['sig_algorithm']}\n"
        )
        
        if cert_details['sans']:
            sans_display = ', '.join(cert_details['sans'][:3])
            if len(cert_details['sans']) > 3:
                sans_display += f" (+{len(cert_details['sans']) - 3} more)"
            cert_info += f"[bold]SANs:[/] {sans_display}\n"
        
        if cert_details['is_self_signed']:
            cert_info += "[bold red]⚠️ Self-Signed Certificate[/bold red]\n"

        console.print(Panel(cert_info, title="[bold #00a8ff]Certificate Details[/]", expand=False))

        # Security details table
        security_table = Table(show_header=False, box=None, padding=(0, 1))
        security_table.add_column(style="bold #00a8ff")
        security_table.add_column()

        # Certificate validity
        validity = scan_results['validity']
        if validity['is_expired']:
            validity_text = "[bold red]❌ Certificate has expired![/bold red]"
        elif validity['is_not_yet_valid']:
            validity_text = f"[bold red]⚠️ Not yet valid until {validity['not_valid_before']:%Y-%m-%d}[/bold red]"
        else:
            days = validity['days_remaining']
            if days > 30:
                validity_text = f"[green]Expires in {days} days ({validity['not_valid_after']:%Y-%m-%d})[/green]"
            elif days > 7:
                validity_text = f"[yellow]Expires in {days} days ({validity['not_valid_after']:%Y-%m-%d})[/yellow]"
            else:
                validity_text = f"[red]Expires in {days} days ({validity['not_valid_after']:%Y-%m-%d})[/red]"
        
        security_table.add_row("Certificate Validity", validity_text)

        # Protocol support
        protocols = scan_results['protocols']
        proto_list = []
        for proto in ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0']:
            if proto in protocols['supported']:
                color = "green" if proto in ['TLSv1.3', 'TLSv1.2'] else "red"
                proto_list.append(f"[{color}]{proto}[/{color}]")
        
        security_table.add_row("Supported Protocols", " ".join(proto_list) if proto_list else "[red]None detected[/red]")

        # Cipher analysis
        cipher = scan_results['cipher_analysis']
        cipher_color = {"Strong": "green", "Moderate": "yellow", "Weak": "red"}[cipher['strength']]
        cipher_text = f"[{cipher_color}]{cipher['name']}[/{cipher_color}]"
        
        cipher_features = []
        if cipher['pfs']:
            cipher_features.append("[green]PFS[/green]")
        if cipher['aead']:
            cipher_features.append("[green]AEAD[/green]")
        
        if cipher_features:
            cipher_text += f" ({', '.join(cipher_features)})"
        
        security_table.add_row("Cipher Suite", cipher_text)

        # Chain status
        chain = scan_results['chain_details']
        if chain['is_trusted'] and chain['is_chain_complete']:
            chain_text = "[green]✔ Valid and trusted[/green]"
        elif chain['is_chain_complete'] and not chain['is_trusted']:
            chain_text = "[yellow]⚠️ Complete but untrusted[/yellow]"
        else:
            chain_text = "[red]❌ Incomplete or invalid[/red]"
        
        if chain['error']:
            chain_text += f"\n[dim red]({chain['error']})[/dim red]"
        
        security_table.add_row("Certificate Chain", chain_text)

        console.print(Panel(security_table, title="[bold #00a8ff]Security Analysis[/]", expand=False))

        # Export option
        if export_format:
            export_results(scan_results, host, export_format)
        return
    
    while True:
        target = console.input("\n[bold]➤ Enter target (e.g., google.com:443): [/]").strip()
        if not target:
            continue
            
        # Parse host and port
        host, port_str = (target.split(':', 1) + ['443'])[:2]
        try:
            port = int(port_str)
        except ValueError:
            console.print(f"[red]Invalid port: {port_str}[/red]")
            continue
        
        # Resolve hostname
        ip = resolve_host(host)
        if not ip:
            continue

        scan_results = {}
        connection_success = False

        # Attempt connection with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with console.status(f"[green]Connecting to {host}:{port} (Attempt {attempt + 1}/{max_retries})...[/]", spinner="bouncingBall"):
                    context = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            # Get certificate and cipher information
                            cert_der = ssock.getpeercert(binary_form=True)
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            cipher_info = ssock.cipher()

                console.print("[green]✔ Connection successful![/green]")

                # Perform comprehensive security analysis
                with console.status("[cyan]Analyzing security configuration...[/]", spinner="dots"):
                    chain_details = check_certificate_chain(host, port)
                    
                    scan_results = {
                        'host_info': {'host': host, 'ip': ip, 'port': port},
                        'protocols': check_protocol_support(host, port),
                        'cipher_analysis': analyze_cipher(cipher_info),
                        'certificate_details': get_certificate_details(cert, chain_details['is_trusted']),
                        'chain_details': chain_details,
                        'security_features': check_security_features(host, port)
                    }

                    # Certificate validity information
                    now = datetime.now(datetime.now().astimezone().tzinfo)
                    scan_results['validity'] = {
                        'not_valid_after': cert.not_valid_after_utc,
                        'not_valid_before': cert.not_valid_before_utc,
                        'days_remaining': (cert.not_valid_after_utc - now).days,
                        'is_expired': now > cert.not_valid_after_utc,
                        'is_not_yet_valid': now < cert.not_valid_before_utc
                    }

                    # Calculate security score
                    grade, score = calculate_tls_score(scan_results)
                    scan_results['tls_score'] = {'grade': grade, 'score': score}

                connection_success = True
                break

            except socket.timeout:
                console.print(f"[yellow]Connection timeout on attempt {attempt + 1}[/yellow]")
                if attempt < max_retries - 1:
                    time.sleep(1)
            except Exception as e:
                console.print(f"[red]Connection failed: {type(e).__name__} - {e}[/red]")
                if attempt < max_retries - 1:
                    time.sleep(1)
                break

        if not connection_success:
            console.print("[bold red]❌ Failed to establish secure connection after all attempts.[/bold red]")
            continue

        # Display comprehensive results
        console.rule(f"[bold]Security Assessment for {host}:{port}[/bold]", style="#00a8ff")
        
        # Overall security grade
        grade, score = scan_results['tls_score']['grade'], scan_results['tls_score']['score']
        grade_colors = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
        grade_color = grade_colors.get(grade, "red")
        
        console.print(Panel(
            f"[{grade_color} bold]{grade}[/]\nScore: {score}/100",
            title="[bold]Security Grade[/]",
            style=grade_color,
            width=25
        ))

        # Certificate information
        cert_details = scan_results['certificate_details']
        cert_info = (
            f"[bold]Common Name:[/] {cert_details['common_name']}\n"
            f"[bold]Issuer:[/] {cert_details['issuer'].get('organizationName', 'N/A')}\n"
            f"[bold]Key Size:[/] {cert_details['key_size']} bits\n"
            f"[bold]Signature:[/] {cert_details['sig_algorithm']}\n"
        )
        
        if cert_details['sans']:
            sans_display = ', '.join(cert_details['sans'][:3])
            if len(cert_details['sans']) > 3:
                sans_display += f" (+{len(cert_details['sans']) - 3} more)"
            cert_info += f"[bold]SANs:[/] {sans_display}\n"
        
        if cert_details['is_self_signed']:
            cert_info += "[bold red]⚠️ Self-Signed Certificate[/bold red]\n"

        console.print(Panel(cert_info, title="[bold #00a8ff]Certificate Details[/]", expand=False))

        # Security details table
        security_table = Table(show_header=False, box=None, padding=(0, 1))
        security_table.add_column(style="bold #00a8ff")
        security_table.add_column()

        # Certificate validity
        validity = scan_results['validity']
        if validity['is_expired']:
            validity_text = "[bold red]❌ Certificate has expired![/bold red]"
        elif validity['is_not_yet_valid']:
            validity_text = f"[bold red]⚠️ Not yet valid until {validity['not_valid_before']:%Y-%m-%d}[/bold red]"
        else:
            days = validity['days_remaining']
            if days > 30:
                validity_text = f"[green]Expires in {days} days ({validity['not_valid_after']:%Y-%m-%d})[/green]"
            elif days > 7:
                validity_text = f"[yellow]Expires in {days} days ({validity['not_valid_after']:%Y-%m-%d})[/yellow]"
            else:
                validity_text = f"[red]Expires in {days} days ({validity['not_valid_after']:%Y-%m-%d})[/red]"
        
        security_table.add_row("Certificate Validity", validity_text)

        # Protocol support
        protocols = scan_results['protocols']
        proto_list = []
        for proto in ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0']:
            if proto in protocols['supported']:
                color = "green" if proto in ['TLSv1.3', 'TLSv1.2'] else "red"
                proto_list.append(f"[{color}]{proto}[/{color}]")
        
        security_table.add_row("Supported Protocols", " ".join(proto_list) if proto_list else "[red]None detected[/red]")

        # Cipher analysis
        cipher = scan_results['cipher_analysis']
        cipher_color = {"Strong": "green", "Moderate": "yellow", "Weak": "red"}[cipher['strength']]
        cipher_text = f"[{cipher_color}]{cipher['name']}[/{cipher_color}]"
        
        cipher_features = []
        if cipher['pfs']:
            cipher_features.append("[green]PFS[/green]")
        if cipher['aead']:
            cipher_features.append("[green]AEAD[/green]")
        
        if cipher_features:
            cipher_text += f" ({', '.join(cipher_features)})"
        
        security_table.add_row("Cipher Suite", cipher_text)

        # Chain status
        chain = scan_results['chain_details']
        if chain['is_trusted'] and chain['is_chain_complete']:
            chain_text = "[green]✔ Valid and trusted[/green]"
        elif chain['is_chain_complete'] and not chain['is_trusted']:
            chain_text = "[yellow]⚠️ Complete but untrusted[/yellow]"
        else:
            chain_text = "[red]❌ Incomplete or invalid[/red]"
        
        if chain['error']:
            chain_text += f"\n[dim red]({chain['error']})[/dim red]"
        
        security_table.add_row("Certificate Chain", chain_text)

        console.print(Panel(security_table, title="[bold #00a8ff]Security Analysis[/]", expand=False))

        # Export option
        export_results(scan_results, host)
        
        # Continue prompt
        if console.input("\n[bold]Scan another target? (y/n): [/]").strip().lower() != 'y':
            break

    console.print("\n[bold #00a8ff]Thank you for using SSL/TLS Security Inspector![/bold #00a8ff]")