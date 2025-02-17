from scapy.all import ARP, Ether, srp

def is_device_on_network(target_ip):
    # Craft ARP request
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and receive the response
    result = srp(packet, timeout=3, verbose=False)[0]

    # Check the result for the target device
    for sent, received in result:
        if received.haslayer(ARP):
            if received[ARP].op == 2:  # '2' is ARP reply
                if received[ARP].psrc == target_ip:
                    return True

    return False

if __name__ == "__main__":
    target_device_ip = "10.10.10.147"  # Change this to the IP address of the device you want to check

    if is_device_on_network(target_device_ip):
        print("The device is connected to the local network.")
    else:
        print("The device is not connected to the local network.")
