# FireSense Firewall 🔥🧱

A custom Python-based firewall with a web interface for managing network traffic, NAT, and security on Linux systems, built using Flask, SocketIO, and NetfilterQueue.

## Features
- Web-based management of firewall rules (allow/drop by IP, protocol, port)
- NAT configuration for network forwarding
- Blacklist IPs and create aliases for simplified rules
- Real-time network traffic and system usage monitoring
- Network scanning for device discovery
- Secure user authentication and encrypted configuration
- Logging and export of packet actions
- Dark/light theme toggle

## Requirements
- Ubuntu 20.04 or later
- Python 3.8 or higher
- Root privileges for iptables and NetfilterQueue
- Two network interfaces (e.g., WAN, LAN) for NAT
- Required Python libraries (installed via `setup.sh`):
  - `flask`
  - `flask-socketio`
  - `cryptography`
  - `netifaces`
  - `psutil`
  - `scapy`
  - `python-nmap`
  - `dnspython`
  - `netfilterqueue`

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/FireSense.git
cd FireSense
```

### Step 2: Install Dependencies
Run the setup script to install system and Python dependencies, enable NAT forwarding, and configure iptables:
```bash
chmod +x setup.sh
sudo ./setup.sh
```

### Step 3: Verify iptables
Check iptables rules to ensure connectivity (SSH, HTTP, HTTPS) and NFQUEUE setup:
```bash
sudo iptables -L -v -n
```

## Usage

### Start the Firewall
Run the firewall with root privileges:
```bash
sudo python3 firewall.py
```
The web interface will be available at `http://<instance-ip>:5000`.

### Access the Web Interface
1. Open `http://<instance-ip>:5000` in a browser.
2. Log in with:
   - Username: `admin`
   - Password: `admin123`
3. Change the password in the "Users" tab immediately.

### Configure NAT
1. Go to the "NAT" tab.
2. Add a rule:
   - Source Network: e.g., `192.168.1.0/24` (LAN)
   - Output Interface: e.g., `ens33` (WAN)
   - Enabled: Yes
3. Save and verify:
   ```bash
   sudo iptables -t nat -L -v -n
   ```

### Stop the Firewall
Press `Ctrl+C` in the terminal. iptables rules are cleaned up automatically.

### View Current Rules
List current iptables rules:
```bash
sudo iptables -L -v -n
```

## Troubleshooting
### If No Internet Connectivity:
Clear iptables to restore access:
```bash
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -t raw -F
sudo iptables -X
```
Check network interfaces:
```bash
ip link
ip addr
```

### If NetfilterQueue Errors:
Verify installation:
```bash
pip3 show netfilterqueue
```
Reinstall dependencies:
```bash
sudo pip3 install -r requirements.txt
```

### If NAT Not Working:
Ensure IP forwarding is enabled:
```bash
sysctl net.ipv4.ip_forward
```
Confirm interface names match NAT rules:
```bash
ip link
```

## Created by - [Your Name] 😊

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
