#!/bin/bash

# SENTRA Installer Script

# ASCII Art for SENTRA
function show_banner() {
    clear
    echo -e "\e[1;35m"
    echo "    _____        _____                                 "
    echo " __|__   |__  __| __  |__  _____ __    _ _____    __   "
    echo "|     \     ||  |/ /     ||     |\ \  //|     | _|  |_ "
    echo "|      \    ||     \     ||     \ \ \// |    _||_    _|"
    echo "|______/  __||__|\__\  __||__|\__\/__/  |___|    |__|  "
    echo "   |_____|      |_____|                                "
    echo "Developed by Rafacuy"
    echo -e "\e[0m"
    echo -e "\e[1;34m           INSTALLATION MANAGER\e[0m"
    echo -e "\e[1m----------------------------------------\e[0m"
}

# Show error message
function show_error() {
    echo -e "\e[1;31m[!] ERROR: $1\e[0m"
    echo
    exit 1
}

# Show status message
function show_status() {
    echo -e "\e[1;34m[*] \e[1;37m$1\e[0m"
}

# Show success message
function show_success() {
    echo -e "\e[1;32m[✓] $1\e[0m"
}

# Check requirements
function check_requirements() {
    # Check for Python
    if ! command -v python3 &>/dev/null; then
        show_error "Python 3 is required but not installed. Please install Python 3 first."
    fi

    # Check for pip
    if ! command -v pip3 &>/dev/null; then
        show_error "pip3 is required but not installed. Please install pip3 first."
    fi

    # Check for requirements file
    if [ ! -f "requirements.txt" ]; then
        show_error "requirements.txt file not found in current directory."
    fi
}

# Main installation function
function install_dependencies() {
    # Filter out standard library packages
    grep -v -E '^(collections|datetime|pathlib)$' requirements.txt > filtered_requirements.txt
    
    show_status "Installing required packages..."
    echo -e "\e[1;30m========================================\e[0m"
    
    if pip3 install -r filtered_requirements.txt; then
        rm filtered_requirements.txt
        echo -e "\e[1;30m========================================\e[0m"
        show_success "All dependencies installed successfully!"
        return 0
    else
        rm filtered_requirements.txt
        show_error "Failed to install dependencies. Check above for errors."
    fi
}

# Main function
function main() {
    show_banner
    
    # Check system requirements
    show_status "Checking system requirements..."
    check_requirements
    show_success "System requirements satisfied"
    echo
    
    # Start installation
    install_dependencies
    
    echo
    show_status "Installation complete! You can now run SENTRA."
    echo
}

# Run main function
main