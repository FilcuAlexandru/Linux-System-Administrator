#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

############################################################################################################
# A PYTHON 3.6 SCRIPT THAT CRAWLS SECURITY INFORMATION ON LINUX SYSTEMS.                                   #
# THE SCRIPT CRAWLS SELINUX, APPARMOR, FIREWALL, SUDO ACCESS, SSH CONFIG, SSL CERTS, AND SECURITY PATCHES. #
# THE SCRIPT DISPLAYS THE COLLECTED INFORMATION AS JSON OUTPUT.                                            #
# VERSION: 0.0.1                                                                                           #
# AUTHOR: ALEXANDRU FILCU                                                                                  #
############################################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class SecurityCrawler:
    """Class for collecting Security information"""
    
    def __init__(self):
        self.info = OrderedDict()
        self.is_vmware = self._detect_vmware()
    
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
    
    def _detect_vmware(self):
        """Detect if running on VMware"""
        systemd_virt = self.run_command("systemd-detect-virt", shell=True)
        return systemd_virt == "vmware" if systemd_virt else False
    
    def get_selinux_status(self):
        """Get SELinux status"""
        selinux_info = OrderedDict()
        
        # Check SELinux status
        selinux_status = self.run_command("getenforce 2>/dev/null || echo 'SELinux not installed'", shell=True)
        selinux_info['selinux_status'] = selinux_status if selinux_status else "N/A"
        
        # Get SELinux policy
        selinux_policy = self.run_command("getsebool -a 2>/dev/null | head -10", shell=True)
        selinux_info['selinux_booleans'] = selinux_policy if selinux_policy else "N/A"
        
        # Get SELinux configuration
        selinux_config = self.run_command("cat /etc/selinux/config 2>/dev/null | grep -v '^#' | grep -v '^$'", shell=True)
        selinux_info['selinux_config'] = selinux_config if selinux_config else "N/A"
        
        # Get SELinux enforcing mode
        selinux_mode = self.run_command("sestatus 2>/dev/null | head -5", shell=True)
        selinux_info['selinux_mode'] = selinux_mode if selinux_mode else "N/A"
        
        self.info['selinux_status'] = selinux_info
    
    def get_apparmor_status(self):
        """Get AppArmor status"""
        apparmor_info = OrderedDict()
        
        # Check AppArmor status
        apparmor_status = self.run_command("aa-status 2>/dev/null | head -10", shell=True)
        apparmor_info['apparmor_status'] = apparmor_status if apparmor_status else "AppArmor not installed"
        
        # Get AppArmor profiles
        apparmor_profiles = self.run_command("cat /etc/apparmor.d/ 2>/dev/null | ls /etc/apparmor.d/ | head -20", shell=True)
        apparmor_info['apparmor_profiles'] = apparmor_profiles if apparmor_profiles else "N/A"
        
        # Check AppArmor kernel support
        apparmor_kernel = self.run_command("cat /sys/module/apparmor/parameters/enabled 2>/dev/null", shell=True)
        apparmor_info['apparmor_kernel_support'] = apparmor_kernel if apparmor_kernel else "N/A"
        
        self.info['apparmor_status'] = apparmor_info
    
    def get_firewall_status(self):
        """Get firewall status"""
        firewall_info = OrderedDict()
        
        # Check iptables
        iptables_status = self.run_command("iptables -L -n 2>/dev/null | head -15", shell=True)
        firewall_info['iptables_rules'] = iptables_status if iptables_status else "N/A"
        
        # Check firewalld
        firewalld_status = self.run_command("systemctl is-active firewalld 2>/dev/null || echo 'Not running'", shell=True)
        firewall_info['firewalld_status'] = firewalld_status if firewalld_status else "N/A"
        
        # Get firewalld zones
        firewalld_zones = self.run_command("firewall-cmd --list-all 2>/dev/null", shell=True)
        firewall_info['firewalld_zones'] = firewalld_zones if firewalld_zones else "N/A"
        
        # Check UFW (Uncomplicated Firewall)
        ufw_status = self.run_command("ufw status 2>/dev/null || echo 'UFW not installed'", shell=True)
        firewall_info['ufw_status'] = ufw_status if ufw_status else "N/A"
        
        # Get nftables status
        nftables_rules = self.run_command("nft list ruleset 2>/dev/null | head -20", shell=True)
        firewall_info['nftables_rules'] = nftables_rules if nftables_rules else "N/A"
        
        self.info['firewall_status'] = firewall_info
    
    def get_sudo_access(self):
        """Get sudo access information"""
        sudo_info = OrderedDict()
        
        # Get sudoers configuration
        sudoers_config = self.run_command("sudo cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'", shell=True)
        sudo_info['sudoers_config'] = sudoers_config if sudoers_config else "N/A"
        
        # Get sudoers.d files
        sudoers_d = self.run_command("ls -la /etc/sudoers.d/ 2>/dev/null", shell=True)
        sudo_info['sudoers_d_files'] = sudoers_d if sudoers_d else "N/A"
        
        # Get sudo log
        sudo_log = self.run_command("sudo grep COMMAND /var/log/auth.log 2>/dev/null | tail -10", shell=True)
        sudo_info['sudo_log'] = sudo_log if sudo_log else "N/A"
        
        self.info['sudo_access'] = sudo_info
    
    def get_ssh_security(self):
        """Get SSH security configuration"""
        ssh_info = OrderedDict()
        
        # Get SSH config
        ssh_config = self.run_command("cat /etc/ssh/sshd_config | grep -v '^#' | grep -v '^$'", shell=True)
        ssh_info['sshd_config'] = ssh_config if ssh_config else "N/A"
        
        # Check SSH key permissions
        ssh_keys = self.run_command("ls -la ~/.ssh/ 2>/dev/null", shell=True)
        ssh_info['ssh_keys_permissions'] = ssh_keys if ssh_keys else "N/A"
        
        # Check authorized keys
        auth_keys = self.run_command("cat ~/.ssh/authorized_keys 2>/dev/null | wc -l", shell=True)
        ssh_info['authorized_keys_count'] = auth_keys if auth_keys else "N/A"
        
        # Check SSH service status
        ssh_status = self.run_command("systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo 'Unknown'", shell=True)
        ssh_info['ssh_service_status'] = ssh_status if ssh_status else "N/A"
        
        # Check SSH port
        ssh_port = self.run_command("grep '^Port' /etc/ssh/sshd_config 2>/dev/null || echo 'Default (22)'", shell=True)
        ssh_info['ssh_port'] = ssh_port if ssh_port else "N/A"
        
        self.info['ssh_security'] = ssh_info
    
    def get_ssl_certificates(self):
        """Get SSL certificate information"""
        ssl_info = OrderedDict()
        
        # Find SSL certificates
        ssl_certs = self.run_command("find /etc/ssl -name '*.crt' 2>/dev/null | head -20", shell=True)
        ssl_info['ssl_certificates'] = ssl_certs if ssl_certs else "N/A"
        
        # Check certificate validity
        cert_validity = self.run_command("for cert in /etc/ssl/certs/*.crt; do openssl x509 -in $cert -noout -dates 2>/dev/null | head -1; done | head -10", shell=True)
        ssl_info['certificate_validity'] = cert_validity if cert_validity else "N/A"
        
        # Check self-signed certificates
        self_signed = self.run_command("openssl x509 -in /etc/ssl/certs/*.crt -noout -issuer -subject 2>/dev/null | grep -B1 'issuer.*subject' | head -10", shell=True)
        ssl_info['self_signed_certs'] = self_signed if self_signed else "N/A"
        
        self.info['ssl_certificates'] = ssl_info
    
    def get_password_policy(self):
        """Get password policy information"""
        password_info = OrderedDict()
        
        # Get login.defs password settings
        login_defs = self.run_command("grep -E 'PASS' /etc/login.defs | grep -v '^#'", shell=True)
        password_info['login_defs'] = login_defs if login_defs else "N/A"
        
        # Get PAM configuration
        pam_config = self.run_command("ls -la /etc/pam.d/", shell=True)
        password_info['pam_config'] = pam_config if pam_config else "N/A"
        
        # Get password complexity settings
        password_complexity = self.run_command("grep -i 'minlen\\|dcredit\\|ucredit\\|lcredit\\|ocredit' /etc/pam.d/* 2>/dev/null | head -10", shell=True)
        password_info['password_complexity'] = password_complexity if password_complexity else "N/A"
        
        self.info['password_policy'] = password_info
    
    def get_user_accounts(self):
        """Get user account information"""
        user_info = OrderedDict()
        
        # Get active users
        active_users = self.run_command("cat /etc/passwd | grep -v 'nologin\\|false' | cut -d: -f1", shell=True)
        user_info['active_users'] = active_users if active_users else "N/A"
        
        # Get system users
        system_users = self.run_command("cat /etc/passwd | awk -F: '$3 < 1000 {print $1}'", shell=True)
        user_info['system_users'] = system_users if system_users else "N/A"
        
        # Get users with UID 0
        root_users = self.run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd", shell=True)
        user_info['root_users'] = root_users if root_users else "N/A"
        
        # Get locked accounts
        locked_accounts = self.run_command("cat /etc/shadow | grep '!' | cut -d: -f1", shell=True)
        user_info['locked_accounts'] = locked_accounts if locked_accounts else "N/A"
        
        self.info['user_accounts'] = user_info
    
    def get_security_updates(self):
        """Get security update information"""
        updates_info = OrderedDict()
        
        # Check for available updates (Ubuntu/Debian)
        apt_updates = self.run_command("apt list --upgradable 2>/dev/null | grep -i 'security\\|critical' | head -10", shell=True)
        updates_info['apt_security_updates'] = apt_updates if apt_updates else "N/A"
        
        # Check for available updates (RHEL/CentOS)
        yum_updates = self.run_command("yum check-update 2>/dev/null | grep -i 'security\\|critical' | head -10", shell=True)
        updates_info['yum_security_updates'] = yum_updates if yum_updates else "N/A"
        
        # Check for SUSE/openSUSE security updates (simplified output)
        zypper_count = self.run_command("zypper list-updates 2>/dev/null | grep -c '^v'", shell=True)
        updates_info['zypper_available_updates_count'] = zypper_count if zypper_count else "0"
        
        # Get only package names and versions (cleaner format)
        zypper_updates_clean = self.run_command("zypper list-updates 2>/dev/null | grep '^v' | awk -F'|' '{print $3, $4, $5}' | head -20", shell=True)
        updates_info['zypper_security_updates'] = zypper_updates_clean if zypper_updates_clean else "N/A"
        
        # Check SUSE patch status (summary only)
        suse_patches = self.run_command("zypper patches 2>/dev/null | tail -5", shell=True)
        updates_info['suse_patches_summary'] = suse_patches if suse_patches else "N/A"
        
        # Check system update status
        update_status = self.run_command("apt upgrade -s 2>/dev/null | tail -5", shell=True)
        updates_info['apt_update_status'] = update_status if update_status else "N/A"
        
        self.info['security_updates'] = updates_info
    
    def get_audit_status(self):
        """Get audit daemon status"""
        audit_info = OrderedDict()
        
        # Check auditd status
        auditd_status = self.run_command("systemctl is-active auditd 2>/dev/null || echo 'Not installed'", shell=True)
        audit_info['auditd_status'] = auditd_status if auditd_status else "N/A"
        
        # Get audit rules
        audit_rules = self.run_command("auditctl -l 2>/dev/null | head -10", shell=True)
        audit_info['audit_rules'] = audit_rules if audit_rules else "N/A"
        
        # Get audit log size
        audit_log = self.run_command("wc -l /var/log/audit/audit.log 2>/dev/null || echo 'N/A'", shell=True)
        audit_info['audit_log_size'] = audit_log if audit_log else "N/A"
        
        self.info['audit_status'] = audit_info
    
    def get_security_modules(self):
        """Get loaded security kernel modules"""
        modules_info = OrderedDict()
        
        # Get loaded security modules
        selinux_module = self.run_command("lsmod | grep selinux", shell=True)
        modules_info['selinux_module'] = selinux_module if selinux_module else "Not loaded"
        
        apparmor_module = self.run_command("lsmod | grep apparmor", shell=True)
        modules_info['apparmor_module'] = apparmor_module if apparmor_module else "Not loaded"
        
        tomoyo_module = self.run_command("lsmod | grep tomoyo", shell=True)
        modules_info['tomoyo_module'] = tomoyo_module if tomoyo_module else "Not loaded"
        
        self.info['security_modules'] = modules_info
    
    def get_vmware_security_info(self):
        """Get VMware-specific security information"""
        vmware_security = OrderedDict()
        
        if self.is_vmware:
            vmware_security['virtualization_type'] = "VMware"
            
            # Check VM security features
            vm_features = self.run_command("dmesg | grep -i 'virtual\\|vmware\\|vt\\|amd' | head -10", shell=True)
            vmware_security['vm_security_features'] = vm_features if vm_features else "N/A"
            
            # Check VMware tools security
            vmware_tools = self.run_command("vmtoolsd --version 2>/dev/null || echo 'Not installed'", shell=True)
            vmware_security['vmware_tools_version'] = vmware_tools if vmware_tools else "N/A"
            
            # Check VM time synchronization
            time_sync = self.run_command("timedatectl status | grep -i 'system clock'", shell=True)
            vmware_security['time_synchronization'] = time_sync if time_sync else "N/A"
        else:
            vmware_security['virtualization_type'] = "Physical Server or Non-VMware VM"
            vmware_security['vm_security_features'] = "N/A"
            vmware_security['vmware_tools_version'] = "N/A"
        
        self.info['vmware_security_info'] = vmware_security
    
    def get_suse_linux_security(self):
        """Get SUSE Linux specific security information"""
        suse_security = OrderedDict()
        
        # Check if SUSE Linux
        suse_check = self.run_command("grep -i 'suse\\|opensuse' /etc/os-release", shell=True)
        
        if suse_check:
            suse_security['os_type'] = "SUSE Linux"
            
            # Get SUSE security module (AppArmor is default on SUSE)
            apparmor_default = self.run_command("systemctl is-active apparmor 2>/dev/null || echo 'Not running'", shell=True)
            suse_security['apparmor_default'] = apparmor_default if apparmor_default else "N/A"
            
            # Get YaST2 security settings
            yast_config = self.run_command("cat /etc/sysconfig/security 2>/dev/null | head -20", shell=True)
            suse_security['yast_security_config'] = yast_config if yast_config else "N/A"
            
            # Get SUSE firewall status
            suse_firewall = self.run_command("systemctl status SuSEfirewall2 2>/dev/null | grep -i 'active'", shell=True)
            suse_security['suse_firewall2'] = suse_firewall if suse_firewall else "N/A"
            
            # Get firewalld on SUSE
            suse_firewalld = self.run_command("systemctl is-active firewalld 2>/dev/null || echo 'Not running'", shell=True)
            suse_security['suse_firewalld'] = suse_firewalld if suse_firewalld else "N/A"
            
            # Get SUSE hardening options
            hardening = self.run_command("cat /etc/sysconfig/hardened 2>/dev/null", shell=True)
            suse_security['suse_hardening'] = hardening if hardening else "N/A"
            
            # Get SUSE package security
            package_audit = self.run_command("rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\\n' 2>/dev/null | grep -i 'security\\|audit' | head -10", shell=True)
            suse_security['rpm_security_packages'] = package_audit if package_audit else "N/A"
            
            # Get SUSE services security configuration
            systemd_config = self.run_command("ls /etc/systemd/system-preset/ 2>/dev/null | head -10", shell=True)
            suse_security['suse_systemd_presets'] = systemd_config if systemd_config else "N/A"
            
            # Check SUSE FIPS mode
            fips_mode = self.run_command("cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 'N/A'", shell=True)
            suse_security['fips_mode'] = fips_mode if fips_mode else "N/A"
            
            # Get SUSE kernel security parameters
            kernel_params = self.run_command("cat /proc/cmdline | grep -o 'apparmor=.*\\|selinux=.*\\|fips=.*'", shell=True)
            suse_security['kernel_security_params'] = kernel_params if kernel_params else "N/A"
            
        else:
            suse_security['os_type'] = "Not SUSE Linux"
            suse_security['apparmor_default'] = "N/A"
            suse_security['yast_security_config'] = "N/A"
        
        self.info['suse_linux_security'] = suse_security
    
    def get_file_integrity(self):
        """Get file integrity checking information"""
        integrity_info = OrderedDict()
        
        # Check AIDE (Advanced Intrusion Detection Environment)
        aide_status = self.run_command("aide --version 2>/dev/null || echo 'Not installed'", shell=True)
        integrity_info['aide_status'] = aide_status if aide_status else "N/A"
        
        # Check Tripwire
        tripwire_status = self.run_command("which tripwire 2>/dev/null || echo 'Not installed'", shell=True)
        integrity_info['tripwire_status'] = tripwire_status if tripwire_status else "N/A"
        
        self.info['file_integrity'] = integrity_info
    
    def get_dmesg_security_info(self):
        """Get security information from dmesg"""
        dmesg_security = self.run_command("dmesg | grep -i 'security\\|selinux\\|apparmor\\|audit\\|denied' | tail -20", shell=True)
        self.info['dmesg_security_info'] = dmesg_security if dmesg_security else "N/A"
    
    def gather_all_info(self):
        """Collect all security information"""
        print("[*] Gathering security information...")
        
        self.get_vmware_security_info()
        print("    [+] VMware/Virtualization security - OK")
        
        self.get_suse_linux_security()
        print("    [+] SUSE Linux security - OK")
        
        self.get_selinux_status()
        print("    [+] SELinux status - OK")
        
        self.get_apparmor_status()
        print("    [+] AppArmor status - OK")
        
        self.get_security_modules()
        print("    [+] Security kernel modules - OK")
        
        self.get_firewall_status()
        print("    [+] Firewall status - OK")
        
        self.get_ssh_security()
        print("    [+] SSH security - OK")
        
        self.get_sudo_access()
        print("    [+] Sudo access - OK")
        
        self.get_user_accounts()
        print("    [+] User accounts - OK")
        
        self.get_password_policy()
        print("    [+] Password policy - OK")
        
        self.get_ssl_certificates()
        print("    [+] SSL certificates - OK")
        
        self.get_audit_status()
        print("    [+] Audit status - OK")
        
        self.get_file_integrity()
        print("    [+] File integrity - OK")
        
        self.get_security_updates()
        print("    [+] Security updates - OK")
        
        self.get_dmesg_security_info()
        print("    [+] dmesg security info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " SECURITY INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = SecurityCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()