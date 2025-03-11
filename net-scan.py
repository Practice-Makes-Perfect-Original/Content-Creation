import os
import platform
import socket
import ipaddress
import argparse
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
    """Main function to execute the ping sweep."""
    print("This project is provided strictly for educational and ethical cybersecurity purposes only. "
      "Unauthorized network scanning without explicit permission from the network owner may violate laws and regulations, "
      "such as the Computer Fraud and Abuse Act (CFAA) and other cybersecurity policies.\n"
      "The author assumes no responsibility for misuse, illegal activity, or damages caused by this software. "
      "Always ensure you have explicit permission before running this script on any network.\n\n"
      "By using this tool, you agree to use it ethically, responsibly, and within legal boundaries."
    )

    parser = argparse.ArgumentParser(description="Ping Sweep Network Scanner")
    parser.add_argument("-s", "--subnet", type=int, choices=[16, 24], required=True, help="Subnet to scan (16 or 24)")
    parser.add_argument("-m", "--mode", choices=["stealth", "normal", "aggressive"], default="normal", help="Scanning mode")
    args = parser.parse_args()
    
    local_ip = get_local_ip()
    if not local_ip:
        return
    
    ip_range = generate_ip_range(local_ip, args.subnet)
    if not ip_range:
        return
    
    live_hosts = scan_network(ip_range, args.mode)
    
    print("\n[INFO] Scan complete.")
    print("[INFO] Live hosts found:")
    for host in live_hosts:
        print(f" - {host}")

if __name__ == "__main__":
    main()
