Python Network Scanner

A simple authorized-use Python Network Scanner that checks IPv4 hosts for open TCP ports.

Features:
- Scan a single IPv4 address
- Scan a private subnet
- Check common TCP ports
- Check custom port ranges
- Export results to CSV or JSON
- Optional reverse DNS lookup
- Optional light banner grabbing
- Permission flag required before scanning

Legal Notice: This tool is for authorized network scanning only. Use it only on networks you own or have permission to test.

Requirements
- Python 3.10+
- No third-party packages required

Usage: Scan your own machine using

```bash
python network_scanner.py --target 1xx.0.0.1 --ports common --timeout 0.2 --i-have-permission
