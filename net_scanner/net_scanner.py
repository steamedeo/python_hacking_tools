#! usr/bin/env python

import scapy.all as scapy
import optparse


# function to get the user arguments
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='target', help='Target IP or IP Range')
    parser.add_option('-i', '--interface', dest='interface', help='The interface name used to scan')
    options, arguments = parser.parse_args()
    return options


# sends ARP request to the network for a certain IP
def scan(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')  # broadcast MAC address
    arp_request_broadcast = broadcast/arp_request
    # send
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface=interface)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients_list.append(client_dict)
        return clients_list


# function to print the result
def print_result(results_list):
    # print header
    print('IP\t\t\tMAC Address')
    print('-----------------------------------------')

    for client in results_list:
            print(client['ip'] + '\t\t' + client['mac'])


options = get_arguments()
scan_result = scan(options.target, options.interface)
print_result(scan_result)

