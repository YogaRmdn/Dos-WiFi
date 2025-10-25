import os
import platform
from icons.colors import *

def clean_screen():
    os.system("cls" if platform == "nt" else "clear")

def header_tools():
    print(f"""{r}
________                       __      __ .__   _____ .__  
\______ \    ____   ______    /  \    /  \|__|_/ ____\|__| 
 |    |  \  /  _ \ /  ___/    \   \/\/   /|  |\   __\ |  | 
 |    `   \(  <_> )\___ \      \        / |  | |  |   |  | 
/_______  / \____//____  >      \__/\  /  |__| |__|   |__|
        \/             \/            \/                    
{rs}{y}#{rs}++++++++++++++++++++++++++++++++++++++++++++++++++++++++{y}#{rs}
< {r}[{rs}+{r}]{rs} Author    : Bang yog                               >
< {r}[{rs}+{r}]{rs} Tools     : Dos WiFi v1                            >
< {r}[{rs}+{r}]{rs} Github    : https://github.com/YogaRmdn            >
{y}#{rs}++++++++++++++++++++++++++++++++++++++++++++++++++++++++{y}#{rs}
""")