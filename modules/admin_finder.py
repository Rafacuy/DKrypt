# modules/admin_finder.py
import requests
import random
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from rich import print
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_exponential
from core.utils import clear_console, load_wordlist

# Inisialisasi Rich Console
console = Console()

# --- Konfigurasi ---
WORDLIST_PATH = Path("wordlists/admin-panels.txt")
REPORT_FILE = "reports/admin_page/bug_reports.txt"
MAX_WORKERS = 20  # Jumlah thread untuk pemindaian konkuren
REQUEST_TIMEOUT = (3, 10) # (connect, read) timeout dalam detik

# --- Daftar User-Agent untuk Rotasi ---
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/605.1.15'
]

# --- Fungsi Utilitas ---

def print_banner():
    """Menampilkan banner aplikasi."""
    console.print(Panel.fit("[b]Admin Page Finder - Enhanced[/b]", 
                         style="#51CBD1", padding=(1, 2)))

def check_wordlist():
    """Memeriksa apakah file wordlist ada."""
    if not WORDLIST_PATH.exists():
        console.print(f"[bold red]Error:[/bold red] Wordlist tidak ditemukan di {WORDLIST_PATH}", style="bold red")
        return False
    return True

def is_valid_url(url):
    """Memvalidasi format URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def save_report(target_url, found_pages):
    """Menyimpan halaman yang ditemukan ke file laporan."""
    report_content = f"""
{'='*60}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target URL: {target_url}
Found Pages: {len(found_pages)}
{'='*60}\n"""
    
    for page in found_pages:
        report_content += f"- {page}\n"
    
    report_content += "\n\n"
    
    try:
        with open(REPORT_FILE, 'a', encoding='utf-8') as f:
            f.write(report_content)
        console.print(f"\n[bold green]Laporan disimpan ke {REPORT_FILE}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error saat menyimpan laporan: {str(e)}[/bold red]")

# --- core logics ---

def is_admin_page(response):
    """
    Mendeteksi halaman admin berdasarkan konten.
    Ini lebih akurat daripada hanya memeriksa status code.
    """
    content = response.text.lower()
    # Indikator umum yang ditemukan di halaman login admin
    indicators = ['login', 'admin', 'password', 'username', 'dashboard', 'log in', 'signin', 'user', 'pass']
    return any(indicator in content for indicator in indicators)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def test_admin_page(url, session):
    """
    Menguji satu URL untuk melihat apakah itu halaman admin.
    - Menggunakan rotasi header HTTP untuk menghindari deteksi.
    - Memeriksa kode status yang relevan (200, 403).
    - Memvalidasi konten halaman untuk akurasi.
    - Mekanisme retry diimplementasikan dengan decorator 'tenacity'.
    """
    try:
        # Rotasi header untuk setiap permintaan
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'keep-alive',
            'X-Requested-With': 'XMLHttpRequest'
        }
        response = session.get(url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True)
        
        # Periksa kode status yang mungkin menunjukkan halaman login (OK, Forbidden)
        if response.status_code in [200, 403]:
            # Lakukan deteksi berbasis konten untuk akurasi yang lebih tinggi
            if is_admin_page(response):
                return True
        return False
    except RequestException:
        # Jika permintaan gagal bahkan setelah coba lagi, kembalikan False
        return False

# --- Fungsi Utama ---

def main():
    """Fungsi utama untuk menjalankan alat."""
    clear_console()
    print_banner()
    
    if not check_wordlist():
        return
    
    try:
        target_url = console.input("[bold cyan]Enter target URL (e.g, http://example.com/): [/bold cyan]").strip()
        
        # URL Validation
        if not is_valid_url(target_url):
            console.print("[bold red]URL Format is invalid. Please insert schema (http:// or https://).[/bold red]")
            return
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation canceled by user.[/bold red]")
        return
    
    try:
        wordlist = load_wordlist(path="wordlists/admin-panels.txt")
        console.print(f"\n[bold green]Loading {len(wordlist)} paths from wordlist[/bold green]")
    except Exception as e:
        console.print(f"[bold red]An error occured while loading wordlist: {str(e)}[/bold red]")
        return
    
    found_pages = []
    
    # Gunakan satu sesi untuk semua permintaan untuk efisiensi
    with requests.Session() as session:
        try:
            # Threading
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                
                # Buat progress bar yang lebih informatif
                progress = Progress(
                    TextColumn("[bold cyan]Scanning..."),
                    BarColumn(),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TextColumn("•"),
                    "[progress.description]{task.description}",
                    TextColumn("•"),
                    TimeRemainingColumn(),
                )

                with progress:
                    # Kirim semua tugas ke thread pool
                    future_to_url = {
                        executor.submit(test_admin_page, urljoin(target_url, '/' + path), session): path 
                        for path in wordlist
                    }
                    
                    task = progress.add_task("path", total=len(wordlist))
                    
                    # Proses hasil saat selesai
                    for future in as_completed(future_to_url):
                        path = future_to_url[future]
                        try:
                            is_found = future.result()
                            if is_found:
                                found_url = urljoin(target_url, '/' + path)
                                console.print(f"\n[bold green]Founded potential admin page: {found_url}[/bold green]")
                                found_pages.append(found_url)
                        except Exception as exc:
                            console.print(f"[bold red]An error occured while testing the path {path}: {exc}[/bold red]")
                        
                        progress.update(task, advance=1, description=f"Trying: [yellow]/{path}[/yellow]")

        except KeyboardInterrupt:
            console.print("\n[bold red]Scanning operation canceled by the user. [/bold red]")
        except Exception as e:
            console.print(f"[bold red]An error occured while scanning: {str(e)}[/bold red]")
    
    if found_pages:
        save_report(target_url, sorted(list(set(found_pages))))
    else:
        console.print("\n[bold yellow]No admin pages found.[/bold yellow]")

if __name__ == "__main__":
    main()
