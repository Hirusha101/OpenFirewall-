# Open Firewall Project

A custom Python-based firewall built using `iptables` for traffic filtering and network security on Linux-based systems.

## Features
- Input and output traffic filtering using `iptables`
- Custom rule creation and deletion
- Logging and error handling
- Simple GUI using `tkinter`

## Requirements
- Ubuntu (or any Debian-based Linux distribution)
- Python 3.8 or higher
- Required Python libraries:
  - `psutil`
  - `tkinter`

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/Hirusha101/OpenFirewall-.git
cd OpenFirewall 
```

### Step 2: Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Grant Execute Permissions (if needed)
```bash
chmod +x openfirewall.py
```

## Usage

### Start the Firewall
To start the firewall:
```bash
python openfirewall.py
```

### Stop the Firewall
To stop the firewall:
```bash
Ctrl + C
```

### View Current Rules
To list the current `iptables` rules:
```bash
sudo iptables -L
```

## Configuration
You can modify the firewall rules by editing the `openfirewall.py` file:
- Modify input and output chains
- Add custom rules for specific IP addresses or ports

## Troubleshooting
### If Permission Denied Errors:
Ensure you have root permissions:
```bash
sudo python openfirewall.py
```

### Reset iptables Rules:
If the firewall becomes unresponsive, reset the rules:
```bash
sudo iptables -F
```

## Created by - Hirusha😊


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



