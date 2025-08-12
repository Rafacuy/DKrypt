# core/banner.py
from rich.console import Console
from time import sleep

console = Console(highlight=False)

def display_header():
        console.print(
            """[red]
    _____        _____                                 
 __|__   |__  __| __  |__  _____ __    _ _____    __   
|     \     ||  |/ /     ||     |\ \  //|     | _|  |_ 
|      \    ||     \     ||     \ \ \// |    _||_    _|
|______/  __||__|\__\  __||__|\__\/__/  |___|    |__|  
   |_____|      |_____|                                 

Developed by Rafacuy (arazz.)
            [/red]"""
        )
    

if __name__ == '__main__':
    display_header()    

