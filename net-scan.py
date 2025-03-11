import os
import platform
import socket
import ipaddress
import subprocess

def get_local_ip():
    """Gets the local machine's IP address."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except socket.gaierror:
        print("[ERROR] Unable to retrieve local IP address.")
        return None

def generate_ip_range(ip, subnet):
    """Generates a list of IP addresses based on the subnet."""
    try:
        network = ipaddress.ip_network(f"{ip}/{subnet}", strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        print("[ERROR] Invalid IP or subnet.")
        return []

def ping_host(ip, timeout=500):
    """Pings a host based on the OS."""
    param = "-n 1 -w" if platform.system().lower() == "windows" else "-c 1 -W"
    command = f"ping {param} {timeout} {ip}"
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception as e:
        print(f"[ERROR] Failed to ping {ip}: {e}")
        return False

def scan_network(ip_range, mode):
    """Scans the network based on the selected mode."""
    live_hosts = []
    timeout = {"stealth": 1000, "normal": 500, "aggressive": 200}.get(mode, 500)
    
    print(f"[INFO] Scanning network with {mode} mode (timeout={timeout}ms)")
    for ip in ip_range:
        if ping_host(ip, timeout):
            live_hosts.append(ip)
            print(f"[+] Host {ip} is online")
    return live_hosts

def main():
    """Main function to execute the ping sweep interactively in an IDE."""
    print(
    "This project is provided strictly for educational and ethical cybersecurity purposes only. "
    "Unauthorized network scanning without explicit permission from the network owner may violate laws and regulations, "
    "such as the Computer Fraud and Abuse Act (CFAA) and other cybersecurity policies.\n"
    "The author assumes no responsibility for misuse, illegal activity, or damages caused by this software. "
    "Always ensure you have explicit permission before running this script on any network.\n\n"
    "By using this tool, you agree to use it ethically, responsibly, and within legal boundaries."
)

    print("Ping Sweep Network Scanner")
    print("Select subnet:")
    print("1. /16")
    print("2. /24")
    subnet_choice = input("Enter choice (1 or 2): ")
    subnet = 16 if subnet_choice == "1" else 24 if subnet_choice == "2" else None
    
    if subnet is None:
        print("[ERROR] Invalid selection.")
        return
    
    print("Select scanning mode:")
    print("1. Stealth")
    print("2. Normal")
    print("3. Aggressive")
    mode_choice = input("Enter choice (1, 2, or 3): ")
    mode_map = {"1": "stealth", "2": "normal", "3": "aggressive"}
    mode = mode_map.get(mode_choice, "normal")
    
    local_ip = get_local_ip()
    if not local_ip:
        return
    
    ip_range = generate_ip_range(local_ip, subnet)
    if not ip_range:
        return
    
    live_hosts = scan_network(ip_range, mode)
    
    print("\n[INFO] Scan complete.")
    print("[INFO] Live hosts found:")
    for host in live_hosts:
        print(f" - {host}")

if __name__ == "__main__":
    main()
