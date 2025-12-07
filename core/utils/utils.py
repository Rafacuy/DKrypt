# core/utils/utils.py
import os
import re
import random
from rich.console import Console
import colorama
from colorama import Fore,Style,init
from core.version import __version__, __status__
from core.ui.banner import get_banner_art
from datetime import datetime

init()

console = Console()

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_wordlist(path='wordlists/subdomain.txt'):
    try:
        with open(path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]⨯  Wordlist file '{path}' not found! Using default list.[/bold red]")
        return [
            'www', 'mail', 'ftp', 'admin', 'blog',
            'dev', 'test', 'api', 'secure', 'portal',
            'webmail', 'shop', 'app', 'cloud', 'm'
        ]
        
def sanitize_filename(name: str) -> str:
    """Removes characters that are invalid for filenames."""
    return re.sub(r'[^\w\-_.]', '_', name)[:100]   
  
def header_banner(tool_name: str):
    """Display a professional header banner for DKrypt tools"""
    VERSION = __version__
    STATUS = __status__
    status_color = "red" if STATUS == "BETA" else "green"
    
    spaced_name = "".join(tool_name.upper())
    
    console.print(
        f"""
[red]                                                                                                                                                                                                                                              
                              ++++++++=   ====                                                                                                      
                          +++++++++++++  ======                                                                                                     
                       ****+++++++++       ==                                                                                                       
                    *******+   +++++++++++======                                                                                                    
                  *******  ++*+++++++++++++++=======                                                                                                
                 *****  +******+++         ==+++======                                                                                              
               *****+ ******+ +*+++++++++++++   ======                                                                                              
              ***** ***** *********++++++++++++++                                                                                                   
             **********+*******          +++++++++++                                                                                                
             *** **** *****                   ++++++++                                                                                              
        [white]    ************%#                       +++++[/red]                              
           ***********%%#                                                         
           *#*******%%##          ***                                          
           ********%%###         ****+=                                             
           ******#%%####      **#*#***+==       +**+*+                               
           *****#%%######        *#******+    **********                               
           *****%%######*       ********     ************                              
            ***#%########*      ********    *************                                                                                           
            **############*   *##*******  *#************                                                                                            
             *##########**   ####** *#*# +####********#                                                                                             
              ######**    ######## ####  ########***#%                                                                                              
                       ##########*####  ###########%%                                                                                               
                #%%%%%%%%%##### #####  #########%%%#                                                                                                
                  %%%%%%%%##  ######  #%##%%%%%%%%                                                                                                  
                      ##%%%%%%%%%%# %%%%%%%%%%%                                                                                                     
                        %%%%%%%#  %%%%%%%%%%                                                                                                        
                                ######                                                                                                                                                                                                                                                        
            [/white]
        
[bold white]D K r y p t[/] • [bold red]{spaced_name}[/]

[bold white]Author      : Rafacuy (arazz.)
[bold red]Time        : {datetime.now().strftime("%H:%M:%S")}
[bold white]Tool ver.   : [bright_yellow]{VERSION}[/] ([bold {status_color}]{STATUS}[/])
            """
    )  
