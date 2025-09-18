# core/utils.py
import os
import re
import random
from rich.console import Console
import colorama
from colorama import Fore,Style,init
from .menu import MenuConfig

init()

console = Console()

# --- Config ---
VERSION = MenuConfig().VERSION
STATUS = MenuConfig().STATUS

# --- Colors and ASCII arts ---
COLORS = ["bright_cyan", "bright_green", "bright_magenta", "bright_yellow", "bright_red", "bright_blue"]
ASCII_ARTS = [
    r"""
                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!
               ~?WuxiW*`   `"#$$$$8!!!!??!!!
             :X- M$$$$       `"T#$T~!8$WUXU~
            :%`  ~#$$$m:        ~!~ ?$$$$$$
          :!`.-   ~T$$$$8xx.  .xWW- ~""##*"
.....   -~~:<` !    ~?T#$$@@W@*?$$      /`
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!
$R@i.~~ !     :   ~$$$$$B$$en:``
?MXT@Wx.~    :     ~"##*$$$$M~
    """,
    r""",
                 __-::..
               _/ _/ _/':.
              / // // / ':.
             / // // /   ::
            =========     ::
           / // // /      **
          / // // /
         (_)(_)(_)
          (_)(_)
           (_)
    """,
    r"""
                            .
                           | \/|
   (\   _                  ) )|/|
       (/            _----. /.'.'
 .-._________..      .' @ _\  .'
 '.._______.   '.   /    (_| .')
   '._____.  /   '-/      | _.'
    '.______ (         ) ) \
      '..____ '._       )  )
         .' __.--\  , ,  // ((
         '.'     |  \/   (_.'(
                 '   \ .'
                  \   (
                   \   '.
                    \ \ '.)
                     '-'-'
    """,
    r"""
                      /|_
                     /   |_
                    /     /
                   /      &gt;
                  (      &gt;
                 /      /
                /     /
               /      /
            __/      \_____
           /'             |
            /     /-\     /
           /      /  \--/
          /     /
         /      /  
        (      &gt;
       /      &gt;
      /     _|
     /  __/
    /_/
    """,
    r"""
                        _--_
                       /   -)
                   ___/___|___
      ____-----=~~///|     ||||~~~==-----_____
    //~////////////~/|     |//|||||\\\\\\\\\\\\\
   ///////////////////|   |///////|\\\\\\\\\\\\\\\
 /////~~~~~~~~~~~~~~~\ |.||/~~~~~~~~~~~~~~~~~`\\\\\
//~                  /\\|\\                      ~\\
                    ///W^\W\
                   ////|||\\\
                   ~~~~~~~~~~
    """,
    r"""
______   _   __                         _   
|  _  \ | | / /                        | |  
| | | | | |/ /   _ __   _   _   _ __   | |_ 
| | | | |    \  | '__| | | | | | '_ \  | __|
| |/ /  | |\  \ | |    | |_| | | |_) | | |_ 
|___/   \_| \_/ |_|     \__, | | .__/   \__|
                         __/ | | |          
                        |___/  |_|          
    """,
    r"""
888b. 8  dP                   w  
8   8 8wdP  8d8b Yb  dP 88b. w8ww
8   8 88Yb  8P    YbdP  8  8  8  
888P' 8  Yb 8      dP   88P'  Y8P
                  dP    8        
    """,
    r"""
    dMMMMb  dMP dMP dMMMMb  dMP dMP dMMMMb dMMMMMMP
   dMP VMP dMP.dMP dMP.dMP dMP.dMP dMP.dMP   dMP   
  dMP dMP dMMMMK" dMMMMK"  VMMMMP dMMMMP"   dMP    
 dMP.aMP dMP"AMF dMP"AMF dA .dMP dMP       dMP     
dMMMMP" dMP dMP dMP dMP  VMMMP" dMP       dMP      
    """,
    r"""
                       )      (
                  /+++=))    ((=+++\
             /++++++++//      \\+++++++++\
          /++++++++++//(  /\  )\\++++++++++\
        /+++++++++++//  \\^^//  \\+++++++++++\
     _/++++++++++++//  {{@::@}}  \\++++++++++++\_
    /+++++++++++++((     {\/}     ))+++++++++++++\
   /+++++++++++++++\\    &lt;**&gt;    //+++++++++++++++\
  /+++++++++++++++++\\  / VV \  //+++++++++++++++++\
 /+++++++++++++++++++\\/******\//+++++++++++++++++++\
|+/|++++++++++/\++++++(***/\***)++++++/\++++++++++|\+\
|/ |+/\+/\+/\/  \+/\++\**|**|**/++/\+/  \/\+/\+/\+| \|
v  |/  V  V  V   V  \+\|*|**|*|/+/  V   v  V  V  \|  v
   v                 /*|*|**|*|*\...              v
                    (**|*|**|*|**). .
                   __\*|*|**|*|*/__. .
                  (vvv(VVV)(VVV)vvv). .
                      ............../ /
                     / ............../
                     ((
    """,
    r"""
                                   __
                               _.-~  )
                    _..--~~~~,'   ,-/     _
                 .-'. . . .'   ,-','    ,' )
               ,'. . . _   ,--~,-'__..-'  ,'
             ,'. . .  (@)' ---~~~~      ,'
            /. . . . '~~             ,-'
           /. . . . .             ,-'
          ; . . . .  - .        ,'
         : . . . .       _     /
        . . . . .          `-.:
       . . . ./  - .          )
      .  . . |  _____..---.._/ _____
~---~~~~----~~~~             ~~
    """,
    r"""
            ______________
      ,===:'.,            `-._
           `:.`---.__         `-._
             `:.     `--.         `.
               \.        `.         `.
       (,,(,    \.         `.   ____,-`.,
    (,'     `/   \.   ,--.___`.'
,  ,'  ,--.  `,   \.;'         `
 `{D, {    \  :    \;
   V,,'    /  /    //
   j;;    /  ,' ,-//.    ,---.      ,
   \;'   /  ,' /  _  \  /  _  \   ,'/
         \   `'  / \  `'  / \  `.' /
          `.___,'   `.__,'   `.__,'
    """,
    r"""
            ''
     .````  ''
   ,' .  ````
  (       ```
    '    ./
   . ;~ ' "
  .     \ . "
 .     "\  .  "
.    " \   .  "
 .     " \   . "
  .     "  \  "
   .      " \ "
    .      " ""
     .    . "  "\
______m_m_______________
            \     "
             "      \
               \     "
                "     \
                |      "
                "      |
                \    ,"
                  ""
                  ""
    """,
    r"""
               ___----------___
        _--                ----__
       -                         ---_
      -___    ____---_              --_
  __---_ .-_--   _ O _-                -
 -      -_-       ---                   -
-   __---------___                       -
- _----                                  -
 -     -_                                 _
 `      _-                                 _
       _                           _-_  _-_ _
      _-                   ____    -_  -   --
      -   _-__   _    __---    -------       -
     _- _-   -_-- -_--                        _
     -_-                                       _
    _-                                          _
    -
    """,
    r"""
                         __,,,,_
       _ ___.--'''`--''// ,-_ `-.
   \`"' ' |  \  \ \\/ / // / ,-  `,_
  /'`  \   |  Y  | \|/ / // / -.,__ `-.
 /&lt;"\    \ \  |  | ||/ // | \/    |`-._`-._
/  _.-.  .-\,___|  _-| / \ \/|_/  |    `-._
`-'  f/ |       / __/ \__  / |__/ |
     `-'       |  -| -|\__ \  |-' |
            __/   /__,-'    ),'  |'
           ((__.-'((____..-' \__,'

    """,
    r"""
                           &lt;\              _
                            \\          _/{
                     _       \\       _-   -_
                   /{        / `\   _-     - -_
                 _~  =      ( @  \ -        -  -_
               _- -   ~-_   \( =\ \           -  -_
             _~  -       ~_ | 1 :\ \      _-~-_ -  -_
           _-   -          ~  |V: \ \  _-~     ~-_-  -_
        _-~   -            /  | :  \ \            ~-_- -_
     _-~    -   _.._      {   | : _-``               ~- _-_
  _-~   -__..--~    ~-_  {   : \:}
=~__.--~~              ~-_\  :  /
                           \ : /__
                          //`Y'--\\
                         &lt;+       \\
                          \\      WWW
    """
    
]

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
    art = random.choice(ASCII_ARTS)
    color1, color2 = random.sample(COLORS, 2)
    color_status = STATUS
    
    if color_status == 'BETA':
      color_status = "red"
    else:
      color_status = "green"
    
    lines = art.strip("\n").split("\n")
    for i, line in enumerate(lines):
        ratio = i / max(1, len(lines) - 1)
        color = f"rgb({int(0 + ratio*255)},{int(255 - ratio*200)},{int(200 - ratio*150)})"
        console.print(f"[{color}]{line}[/]")

    console.print()

    # Stylish tool name (glow effect)
    tool_display = f"⚡ {tool_name.upper()} ⚡"
    border = "═" * (len(tool_display) + 6)

    console.print(
        f"[bold {color1}]{border}[/]\n"
        f"[bold {color2}]   {tool_display}   [/]\n"
        f"[bold {color1}]{border}[/]"
    )

    console.print()
    panel_text = (
        f"[bold {color2}]⚔️  DKrypt Pentesting Suite ⚔️[/]\n"
        f"[white]Ver    :[/] [bold {color1}]{VERSION}[/][bold {color_status}] {STATUS}[/]\n"
        f"[white]Author :[/] [bold {color1}]Rafacuy (arazz.)[/]\n"
        f"[white]Github :[/] [underline {color2}]https://github.com/Rafacuy/DKrypt[/]"
    )
    console.rule(style=f"bold {color1}")
    console.print(panel_text, justify="left")
    console.rule(style=f"bold {color1}")

