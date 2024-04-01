import scapy.all as scapy

def scan(ip):
    # Creating an ARP request packet
    arp_request = scapy.ARP(pdst=ip)
    
    # Creating an Ethernet frame to encapsulate ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine Ethernet frame and ARP request packet
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and receive the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Parse the response
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

# Example usage
target_ip = "192.168.1.1/24"  # Specify the IP range you want to scan
scan_result = scan(target_ip)
print_result(scan_result)
