#!/bin/bash
# Multi-Tool Installation Script for Replit

echo "==================================================================="
echo "  Multi-Tool: Network Reconnaissance & Website Analysis Installer  "
echo "==================================================================="

# Install Python dependencies
#Note:  This assumes requirements_list.txt exists in the same directory.  Adjust path if needed.
python -m pip install -r requirements_list.txt

# Create directories if they don't exist
mkdir -p multi_tool/cache
mkdir -p multi_tool/modules/screenshots

# Set up file permissions (modified for Replit context)
chmod +x run_interactive.sh
chmod +x main.py
chmod +x interactive.py

#The rest of the original script is adapted for Replit
INSTALL_DIR="./multi_tool" #Adjusted for Replit
BIN_LINK="./multi-tool" #Adjusted for Replit

echo -e "\nCreating installation directory...${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"

echo -e "\nCopying files to installation directory..."

# Check if this is being run from the source directory or as a standalone script
if [ -d "./multi_tool" ]; then
    # Running from source directory
    cp -r ./multi_tool "$INSTALL_DIR/"
    cp ./main.py "$INSTALL_DIR/"
    cp ./interactive.py "$INSTALL_DIR/"
    cp ./setup.py "$INSTALL_DIR/" 2>/dev/null || echo "No setup.py found, skipping"
    cp ./README.md "$INSTALL_DIR/" 2>/dev/null || echo "No README.md found, skipping"
    cp ./requirements.txt "$INSTALL_DIR/" 2>/dev/null || echo "No requirements.txt found, skipping"
else
    echo -e "${RED}Multi-Tool source files not found in current directory!${NC}"
    exit 1
fi

# Check for requirements file (modified for Replit;  Assumes requirements_list.txt exists)
if [ -f "./requirements_list.txt" ]; then
    echo -e "\nCopying requirements file..."
    cp ./requirements_list.txt "$INSTALL_DIR/requirements.txt"
else
    echo -e "\nError: requirements_list.txt not found!"
    exit 1
fi


# Set up virtual environment (modified for Replit)
echo -e "\nSetting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install Python dependencies (already done above, but kept for consistency)
echo -e "\nInstalling Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
"$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR"


# Create launcher script (modified for Replit)
echo -e "\nCreating launcher script..."
cat > "$INSTALL_DIR/multi-tool" << EOF
#!/bin/bash
source "$INSTALL_DIR/venv/bin/activate"
python3 "$INSTALL_DIR/main.py" "$@"
EOF

chmod +x "$INSTALL_DIR/multi-tool"

# Create symlink (modified for Replit)
ln -sf "$INSTALL_DIR/multi-tool" "$BIN_LINK"


# Create an alias for running the interactive mode directly (modified for Replit)
cat > "$INSTALL_DIR/multi-tool-interactive" << EOF
#!/bin/bash
source "$INSTALL_DIR/venv/bin/activate"
python3 "$INSTALL_DIR/interactive.py" "$@"
EOF

chmod +x "$INSTALL_DIR/multi-tool-interactive"
ln -sf "$INSTALL_DIR/multi-tool-interactive" "./multi-tool-interactive"


echo "Installation complete!"
echo "You can now run the application using:"
echo "1. Web interface: Click the Run button"
echo "2. Interactive mode: ./run_interactive.sh"
echo "3. CLI mode: ./multi-tool [command] [options]"