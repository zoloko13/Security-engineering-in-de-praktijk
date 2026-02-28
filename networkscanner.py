import sys
import ipaddress
from scapy.all import IP, TCP, sr1, conf, ICMP
from scapy.layers.l2 import ARP, Ether, srp
import nmap
import socket

# Silence Scapy verbosity and no infinite retries
conf.verb = 0
conf.timeout = 1

def is_host_up(host):
    packet = IP(dst=str(host)) / ICMP()
    response = sr1(packet, timeout=1, retry=0)
    return response is not None

def get_mac_address(ip):
    arp_request = ARP(pdst=str(ip))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, unanswered = srp(packet, timeout=1, retry=1, verbose=0)

    for sent, received in answered:
        return received.hwsrc  # MAC address

    return None

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(str(ip))
        return hostname
    except socket.herror:
        return None

def tcp_syn_scan(host, ports):
    
    """
    This function attempts to start a TCP connection with ports on the host it's scanning and if it gets a positive hit, it will put this in a list.
    As soon as the open ports are detected, it will display them on the terminal
    """
    
    print(f"\nStarting SYN scan on {host} to detect ports")
    open_ports = []

    for port in ports:
        packet = IP(dst=str(host)) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, retry=1)

        if response:
            if response.haslayer(TCP):           
                if response[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)      # Adds the port to the list

                    # Send RST to gracefully close connection
                    rst_packet = IP(dst=str(host)) / TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=1, retry=1)

    return open_ports
2

def run_nmap_scan(host):
    print(f"Nmap OS and service detection running on {host}")

    nm = nmap.PortScanner()
    nm.scan(host, arguments='-O -sV')

    if host in nm.all_hosts():
        # OS detection
        if 'osmatch' in nm[host]:
            for os in nm[host]['osmatch']:
                print(f"Possible OS: {os['name']} (Accuracy: {os['accuracy']}%)")

        # Service detection
        for protocol in nm[host].all_protocols():
            ports = nm[host][protocol].keys()
            for port in ports:
                service = nm[host][protocol][port]
                print(f"Port {port}/{protocol}: {service['name']} {service.get('version', '')}")
    else:
        print("No Nmap data available.")


def get_hosts():
    print("Choose scan type:")
    print("1. Single host")
    print("2. Range of hosts")

    choice = input("Enter choice (1 or 2): ")

    if choice == "1":
        host = input("Enter IP address: ")
        return [ipaddress.ip_address(host)]

    elif choice == "2":
        user_input = input(
            "Enter a full network (like 192.168.1.0/24) "
            "or a network range (like 192.168.0.1-192.168.0.50): "
        )

        if "/" in user_input:
            net = ipaddress.ip_network(user_input, strict=False)
            return list(net.hosts())

        elif "-" in user_input:
            start_ip_str, end_ip_str = user_input.split("-")
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())

            if start_ip > end_ip:
                print("Start IP must be smaller than End IP")
                sys.exit(1)

        hosts = []
        current_ip = start_ip
        while current_ip <= end_ip:
            hosts.append(current_ip)
            current_ip += 1

        return hosts
    
    else:
        print("Invalid choice.")
        sys.exit(1)


def main():
    """
    This function makes sure that the results of other functions get printed to the terminal.
    """
    print("Networkscanner week 2")

    hosts = get_hosts()

    port_range = input("Enter port range (e.g., 1-1024): ")
    start_port, end_port = map(int, port_range.split('-'))
    ports = range(start_port, end_port + 1)

    for host in hosts:

        if not is_host_up(host):
            print(f"{host} is not up.")
            continue
        
        open_ports = tcp_syn_scan(host, ports)
        
        if open_ports:
            mac = get_mac_address(host)
            hostname = get_hostname(host)

            macaddr = mac if mac else "No mac found"
            name_of_host = hostname if hostname else "No hostname found"

            print(f"\nHost: {host}")
            print(f"Hostname: {name_of_host}")
            print(f"MAC Address: {macaddr}")


            if mac:
                print(f"Open ports found on {host} (MAC: {mac}): {open_ports}")
            
            else:
                print(f"Open ports found on {host} (MAC: Not found): {open_ports}")
    
            run_nmap_scan(str(host))
  


if __name__ == "__main__":
    main()