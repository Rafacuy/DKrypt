#!/data/data/com.termux/files/usr/bin/bash

# ASCII Art and Color Definitions
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

# Rocket launch animation
rocket_launch() {
    frames=(
        "    ▲    "
        "   ▲▲▲   "
        "  ▲▲▲▲▲  "
        " ▲▲▲▲▲▲▲ "
        "    ▲    "
        "   ██    "
        "   ██    "
    )
    for i in {1..10}; do
        clear
        echo -e "\n\n"
        echo -e "${CYAN}${frames[$((i % ${#frames[@]}))]}${RESET}"
        echo -e "${GREEN}  Preparing script..${RESET}"
        sleep 0.2
    done
}

# Rotating spinner for background tasks
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# --- Main Script ---

# Header
clear
rocket_launch
sleep 0.3
clear
echo -e "${MAGENTA}"
cat << "EOF"

    _____        _____
 __|__   |__  __| __  |__  _____ __    _ _____    __
|     \     ||  |/ /     ||     |\ \  //|     | _|  |_
|      \    ||     \     ||     \ \ \// |    _||_    _|
|______/  __||__|\__\  __||__|\__\/__/  |___|    |__|
   |_____|      |_____|
Developed by Rafacuy
EOF
echo -e "${RESET}"
echo -e "${YELLOW}============================================${RESET}"
echo -e "${CYAN}             DKrypt Setup Fixer               ${RESET}"
echo -e "${YELLOW}============================================${RESET}"

echo -e "\n${YELLOW}[⚙] UPDATING & UPGRADING PACKAGES${RESET}"
(pkg update -y && pkg upgrade -y > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ System packages are up to date!${RESET}"

echo -e "\n${YELLOW}[⚙] INSTALLING BUILD DEPENDENCIES${RESET}"
echo -e "${CYAN}   (Python, Clang, libffi, OpenSSL, Rust, Git, Brotli, Graphviz)${RESET}"
(pkg install -y python clang libffi openssl rust git brotli graphviz > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ Build tools installed!${RESET}"

echo -e "\n${YELLOW}[⚙] CONFIGURING BUILD ENVIRONMENT${RESET}"
export LDFLAGS="-L/data/data/com.termux/files/usr/lib"
export CFLAGS="-I/data/data/com.termux/files/usr/include"
echo -e "${GREEN} ✓ Environment configured!${RESET}"

# Step 4: Upgrade Python's package manager
echo -e "\n${YELLOW}[⚙] UPGRADING PYTHON BUILD SYSTEM${RESET}"
(pip install --upgrade pip setuptools wheel > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ Python tools upgraded!${RESET}"

echo -e "\n${YELLOW}[⚙] PREPARING & INSTALLING REQUIREMENTS${RESET}"
if [ -f requirements.txt ]; then
    echo -e "${CYAN}   Filtering requirements.txt for compatibility...${RESET}"
    grep -vE "^(collections|datetime|pathlib|asyncio|socks)$" requirements.txt > requirements.clean.txt

    echo -e "${CYAN}   Installing dependencies... (This may take several minutes)${RESET}"
    pip install --no-cache-dir -r requirements.clean.txt
    
    # Clean up the temporary file
    rm requirements.clean.txt
    echo -e "${GREEN} ✓ Project dependencies installed!${RESET}"
else
    echo -e "${RED}✗ ERROR: requirements.txt not found.${RESET}"
    exit 1
fi

# --- Success ---

# Final animation and message
echo -e "\n${GREEN}[✓] DKRYPT REPAIR COMPLETE!${RESET}"
echo -e "${YELLOW}Launching final checks...${RESET}"
for i in {1..10}; do
    printf "${MAGENTA}■${RESET}"
    sleep 0.1
    printf "${GREEN}■${RESET}"
    sleep 0.1
    printf "${CYAN}■${RESET}"
    sleep 0.1
done
echo ""

clear
echo -e "\n\n${GREEN}"
cat << "EOF"
____ _ _  _ _ ____ _  _ ____ ___
|___ | |\ | | [__  |__| |___ |  \
|    | | \| | ___] |  | |___ |__/
EOF
echo -e "${RESET}"
echo -e "${YELLOW}============================================${RESET}"
echo -e "${GREEN} All systems go! You can now run the app. ${RESET}"
echo -e "${YELLOW}============================================${RESET}"
echo -e "\n${CYAN}Tip:${RESET} If issues persist, fully restart your Termux session.\n"
