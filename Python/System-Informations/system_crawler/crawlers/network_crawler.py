#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

############################################################################################################################
# A Python 3.6 script that verifies Network informations on a Linux server.                                                #
# The script verifies the following: network interfaces, IP addresses, routing, DNS, network statistics, and connectivity. #
# Version: 0.0.1                                                                                                           #
# Author: Alexandru Filcu                                                                                                  #
############################################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class NetworkCrawler:
    """Class for collecting Network information"""
    
    def __init__(self):
        self.info = OrderedDict()
    
    def run_command(self, command, shell=False):
        """Execute a shell command and return the output"""
        try:
            result = subprocess.Popen(
                command,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = result.communicate()
            
            if result.returncode != 0:
                return None
            
            return stdout.strip() if stdout else "N/A"
        
        except Exception as e:
            return None
    
    def get_network_interfaces(self):
        """Get network interfaces"""
        interfaces = self.run_command("ip link show", shell=True)
        self.info['network_interfaces'] = interfaces if interfaces else "N/A"
    
    def get_ip_addresses(self):
        """Get IP addresses (IPv4 and IPv6)"""
        ip_addresses = self.run_command("ip addr show", shell=True)
        self.info['ip_addresses'] = ip_addresses if ip_addresses else "N/A"
    
    def get_ifconfig(self):
        """Get ifconfig information"""
        ifconfig_output = self.run_command("ifconfig 2>/dev/null || ip addr show", shell=True)
        self.info['ifconfig'] = ifconfig_output if ifconfig_output else "N/A"
    
    def get_routing_table(self):
        """Get routing table"""
        routing = self.run_command("ip route show", shell=True)
        self.info['routing_table'] = routing if routing else "N/A"
    
    def get_routing_table_detailed(self):
        """Get detailed routing table"""
        routing_detailed = self.run_command("route -n", shell=True)
        self.info['routing_table_detailed'] = routing_detailed if routing_detailed else "N/A"
    
    def get_default_gateway(self):
        """Get default gateway"""
        gateway = self.run_command("ip route | grep default", shell=True)
        self.info['default_gateway'] = gateway if gateway else "N/A"
    
    def get_dns_configuration(self):
        """Get DNS configuration"""
        dns_config = self.run_command("cat /etc/resolv.conf", shell=True)
        self.info['dns_configuration'] = dns_config if dns_config else "N/A"
    
    def get_hostname_and_domain(self):
        """Get hostname and domain"""
        hostname_info = OrderedDict()
        
        # Get hostname
        hostname = self.run_command("hostname", shell=True)
        hostname_info['hostname'] = hostname if hostname else "N/A"
        
        # Get FQDN
        fqdn = self.run_command("hostname -f 2>/dev/null || hostname", shell=True)
        hostname_info['fqdn'] = fqdn if fqdn else "N/A"
        
        # Get domain
        domain = self.run_command("hostname -d 2>/dev/null || echo 'N/A'", shell=True)
        hostname_info['domain'] = domain if domain else "N/A"
        
        self.info['hostname_and_domain'] = hostname_info
    
    def get_interface_statistics(self):
        """Get interface statistics"""
        ifstat = OrderedDict()
        
        # Get interface stats
        ip_stats = self.run_command("ip -s link", shell=True)
        ifstat['ip_statistics'] = ip_stats if ip_stats else "N/A"
        
        # Get detailed stats
        netstat_check = self.run_command("which netstat", shell=True)
        if netstat_check:
            netstat_output = self.run_command("netstat -i", shell=True)
            ifstat['netstat_interfaces'] = netstat_output if netstat_output else "N/A"
        else:
            ifstat['netstat_interfaces'] = "netstat not available"
        
        self.info['interface_statistics'] = ifstat
    
    def get_network_protocols(self):
        """Get network protocol statistics"""
        protocols = OrderedDict()
        
        # Get TCP statistics
        tcp_stats = self.run_command("netstat -s 2>/dev/null | grep -i tcp || ss -s 2>/dev/null | grep -i tcp", shell=True)
        protocols['tcp_statistics'] = tcp_stats if tcp_stats else "N/A"
        
        # Get UDP statistics
        udp_stats = self.run_command("netstat -s 2>/dev/null | grep -i udp || ss -s 2>/dev/null | grep -i udp", shell=True)
        protocols['udp_statistics'] = udp_stats if udp_stats else "N/A"
        
        # Get IP statistics
        ip_stats = self.run_command("netstat -s 2>/dev/null | grep -i 'IP' | head -10 || ss -s 2>/dev/null", shell=True)
        protocols['ip_statistics'] = ip_stats if ip_stats else "N/A"
        
        self.info['protocol_statistics'] = protocols
    
    def get_network_connections(self):
        """Get network connections"""
        connections = OrderedDict()
        
        # Get established connections
        established = self.run_command("netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || ss -an | grep ESTABLISHED | wc -l", shell=True)
        connections['established_connections'] = established if established else "N/A"
        
        # Get listening ports
        listening = self.run_command("netstat -an 2>/dev/null | grep LISTEN || ss -an | grep LISTEN", shell=True)
        connections['listening_ports'] = listening if listening else "N/A"
        
        # Get all connections summary
        all_connections = self.run_command("netstat -an 2>/dev/null | tail -1 || ss -an | tail -1", shell=True)
        connections['connections_summary'] = all_connections if all_connections else "N/A"
        
        self.info['network_connections'] = connections
    
    def get_arp_table(self):
        """Get ARP table"""
        arp_table = self.run_command("arp -a", shell=True)
        self.info['arp_table'] = arp_table if arp_table else "N/A"
    
    def get_mac_addresses(self):
        """Get MAC addresses"""
        mac_addresses = self.run_command("ip link show | grep -i 'link/ether'", shell=True)
        self.info['mac_addresses'] = mac_addresses if mac_addresses else "N/A"
    
    def get_network_devices_pci(self):
        """Get network devices from PCI"""
        network_pci = self.run_command("lspci | grep -i 'network\\|ethernet'", shell=True)
        self.info['network_devices_pci'] = network_pci if network_pci else "N/A"
    
    def get_network_drivers(self):
        """Get network drivers"""
        drivers = OrderedDict()
        
        # Get loaded network drivers
        loaded_drivers = self.run_command("lsmod | grep -E 'e1000|bnx2|virtio|mlx|igb|ixgbe'", shell=True)
        drivers['loaded_drivers'] = loaded_drivers if loaded_drivers else "N/A"
        
        # Get all network kernel modules
        all_modules = self.run_command("ls /sys/class/net/", shell=True)
        drivers['network_interfaces_sysfs'] = all_modules if all_modules else "N/A"
        
        self.info['network_drivers'] = drivers
    
    def get_firewall_status(self):
        """Get firewall status"""
        firewall = OrderedDict()
        
        # Check iptables
        iptables_check = self.run_command("which iptables", shell=True)
        if iptables_check:
            iptables_rules = self.run_command("iptables -L -n 2>/dev/null | head -20", shell=True)
            firewall['iptables_rules'] = iptables_rules if iptables_rules else "N/A"
        else:
            firewall['iptables_rules'] = "iptables not available"
        
        # Check firewalld
        firewalld_check = self.run_command("systemctl status firewalld 2>/dev/null | grep 'Active'", shell=True)
        firewall['firewalld_status'] = firewalld_check if firewalld_check else "N/A"
        
        # Check ufw
        ufw_check = self.run_command("ufw status 2>/dev/null || echo 'UFW not available'", shell=True)
        firewall['ufw_status'] = ufw_check if ufw_check else "N/A"
        
        self.info['firewall_status'] = firewall
    
    def get_network_services(self):
        """Get network services information"""
        services = OrderedDict()
        
        # Get listening services with netstat
        netstat_listen = self.run_command("netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null", shell=True)
        services['listening_services'] = netstat_listen if netstat_listen else "N/A"
        
        self.info['network_services'] = services
    
    def get_interface_speed_duplex(self):
        """Get interface speed and duplex settings"""
        speed_duplex = OrderedDict()
        
        # Get ethtool info if available
        ethtool_check = self.run_command("which ethtool", shell=True)
        if ethtool_check:
            interfaces = self.run_command("ls /sys/class/net/", shell=True)
            if interfaces:
                for interface in interfaces.split('\n'):
                    if interface.strip():
                        ethtool_output = self.run_command("ethtool {} 2>/dev/null | grep -i 'speed\\|duplex'".format(interface.strip()), shell=True)
                        if ethtool_output:
                            speed_duplex[interface.strip()] = ethtool_output
        else:
            speed_duplex['ethtool'] = "ethtool not available"
        
        self.info['interface_speed_duplex'] = speed_duplex if speed_duplex else "N/A"
    
    def get_network_config_files(self):
        """Get network configuration files"""
        config_files = OrderedDict()
        
        # Get /etc/hosts
        hosts = self.run_command("cat /etc/hosts", shell=True)
        config_files['etc_hosts'] = hosts if hosts else "N/A"
        
        # Get /etc/hostname
        hostname_file = self.run_command("cat /etc/hostname 2>/dev/null || echo 'N/A'", shell=True)
        config_files['etc_hostname'] = hostname_file if hostname_file else "N/A"
        
        self.info['network_config_files'] = config_files
    
    def get_packet_loss_test(self):
        """Test packet loss with ping"""
        ping_test = self.run_command("ping -c 4 8.8.8.8 2>/dev/null | tail -2 || echo 'Ping test failed'", shell=True)
        self.info['ping_connectivity_test'] = ping_test if ping_test else "N/A"
    
    def get_dmesg_network_info(self):
        """Get network information from dmesg"""
        dmesg_network = self.run_command("dmesg | grep -i 'network\\|ethernet\\|nic\\|link' | tail -20", shell=True)
        self.info['dmesg_network_info'] = dmesg_network if dmesg_network else "N/A"
    
    def gather_all_info(self):
        """Collect all network information"""
        print("[*] Gathering network information...")
        
        self.get_hostname_and_domain()
        print("    [+] Hostname and domain - OK")
        
        self.get_network_interfaces()
        print("    [+] Network interfaces - OK")
        
        self.get_ip_addresses()
        print("    [+] IP addresses - OK")
        
        self.get_mac_addresses()
        print("    [+] MAC addresses - OK")
        
        self.get_routing_table()
        print("    [+] Routing table - OK")
        
        self.get_routing_table_detailed()
        print("    [+] Routing table detailed - OK")
        
        self.get_default_gateway()
        print("    [+] Default gateway - OK")
        
        self.get_dns_configuration()
        print("    [+] DNS configuration - OK")
        
        self.get_interface_statistics()
        print("    [+] Interface statistics - OK")
        
        self.get_network_protocols()
        print("    [+] Protocol statistics - OK")
        
        self.get_network_connections()
        print("    [+] Network connections - OK")
        
        self.get_arp_table()
        print("    [+] ARP table - OK")
        
        self.get_network_devices_pci()
        print("    [+] Network devices (PCI) - OK")
        
        self.get_network_drivers()
        print("    [+] Network drivers - OK")
        
        self.get_interface_speed_duplex()
        print("    [+] Interface speed/duplex - OK")
        
        self.get_firewall_status()
        print("    [+] Firewall status - OK")
        
        self.get_network_services()
        print("    [+] Network services - OK")
        
        self.get_network_config_files()
        print("    [+] Network config files - OK")
        
        self.get_ifconfig()
        print("    [+] ifconfig - OK")
        
        self.get_packet_loss_test()
        print("    [+] Connectivity test - OK")
        
        self.get_dmesg_network_info()
        print("    [+] dmesg network info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " NETWORK INFORMATIONS REPORT ".center(78) + "║")
        print("╚" + "═" * 78 + "╝")
        
        for key, value in self.info.items():
            print("\n[{}]".format(key.upper().replace('_', ' ')))
            print("-" * 80)
            
            if isinstance(value, dict):
                # Display nested dictionary
                for sub_key, sub_value in value.items():
                    print("\n  {}:".format(sub_key.upper().replace('_', ' ')))
                    if verbose:
                        print("  {}".format(sub_value.replace('\n', '\n  ') if isinstance(sub_value, str) else str(sub_value)))
                    else:
                        if isinstance(sub_value, str):
                            first_line = sub_value.split('\n')[0] if sub_value else "N/A"
                        else:
                            first_line = str(sub_value)
                        print("  {}".format(first_line))
            else:
                if verbose:
                    print(value)
                else:
                    # Display only first line for compact mode
                    first_line = value.split('\n')[0] if isinstance(value, str) else str(value)
                    print(first_line)
    
    def export_to_dict(self):
        """Export information to a dictionary"""
        return dict(self.info)
    
    def export_to_json(self, pretty=True, output_file=None):
        """Export information to JSON format"""
        # Flatten nested OrderedDict/dict to ensure JSON serialization
        data = self._flatten_for_json(self.info)
        
        if pretty:
            json_output = json.dumps(data, indent=2)
        else:
            json_output = json.dumps(data)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(json_output)
                print("[+] JSON output written to: {}".format(output_file))
                return None
            except Exception as e:
                print("[-] Error writing to file: {}".format(str(e)))
                return json_output
        else:
            return json_output
    
    def _flatten_for_json(self, obj):
        """Convert OrderedDict and nested structures to regular dicts for JSON"""
        if isinstance(obj, OrderedDict):
            return {k: self._flatten_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            return {k: self._flatten_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._flatten_for_json(item) for item in obj]
        else:
            return obj


def main():
    """Main function"""
    crawler = NetworkCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()