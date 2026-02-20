#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

############################################################################################
# A PYTHON 3.6 SCRIPT THAT CRAWLS AND VALIDATES AUDIO CONFIGURATION ON LINUX SYSTEMS.      #
# IT CRAWLS AUDIO CARDS, AUDIO DRIVERS, ALSA, PULSEAUDIO, JACK, AND SYSTEM AUDIO SETTINGS. #
# THE SCRIPT DISPLAYS THE COLLECTED INFORMATION AS JSON OUTPUT.                            #
# VERSION: 0.0.1                                                                           #
# AUTHOR: ALEXANDRU FILCU                                                                  #
############################################################################################

######################
# Import handy tools #
######################

import subprocess
import sys
import json
from collections import OrderedDict


class AudioCrawler:
    """Class for collecting Audio device information"""
    
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
    
    def get_audio_devices_pci(self):
        """Get audio devices from PCI"""
        audio_pci = OrderedDict()
        
        # Get audio devices from lspci
        audio_devices = self.run_command("lspci | grep -i 'audio\\|sound'", shell=True)
        audio_pci['audio_devices'] = audio_devices if audio_devices else "N/A"
        
        # Get detailed audio device info
        audio_detailed = self.run_command("lspci -k | grep -A 2 -i 'audio\\|sound'", shell=True)
        audio_pci['audio_devices_detailed'] = audio_detailed if audio_detailed else "N/A"
        
        # Get audio device IDs
        audio_ids = self.run_command("lspci -n | grep -i '04'", shell=True)
        audio_pci['audio_device_ids'] = audio_ids if audio_ids else "N/A"
        
        self.info['audio_devices_pci'] = audio_pci
    
    def get_alsa_info(self):
        """Get ALSA (Advanced Linux Sound Architecture) information"""
        alsa_info = OrderedDict()
        
        # Check if aplay is available
        aplay_check = self.run_command("which aplay", shell=True)
        
        if aplay_check:
            # Get ALSA devices
            alsa_devices = self.run_command("aplay -l", shell=True)
            alsa_info['alsa_playback_devices'] = alsa_devices if alsa_devices else "N/A"
            
            # Get ALSA recording devices
            alsa_record = self.run_command("arecord -l", shell=True)
            alsa_info['alsa_record_devices'] = alsa_record if alsa_record else "N/A"
        else:
            alsa_info['alsa_playback_devices'] = "aplay not available"
            alsa_info['alsa_record_devices'] = "arecord not available"
        
        # Get ALSA configuration
        alsa_config = self.run_command("cat /proc/asound/cards", shell=True)
        alsa_info['alsa_cards'] = alsa_config if alsa_config else "N/A"
        
        # Get detailed ALSA info
        alsa_detailed = self.run_command("cat /proc/asound/version", shell=True)
        alsa_info['alsa_version'] = alsa_detailed if alsa_detailed else "N/A"
        
        # Get mixers
        mixer_info = self.run_command("amixer 2>/dev/null | head -50", shell=True)
        alsa_info['alsa_mixer_info'] = mixer_info if mixer_info else "N/A"
        
        self.info['alsa_info'] = alsa_info
    
    def get_pulseaudio_info(self):
        """Get PulseAudio information"""
        pulseaudio_info = OrderedDict()
        
        # Check if PulseAudio is running
        pulseaudio_check = self.run_command("systemctl is-active pulseaudio 2>/dev/null || pgrep pulseaudio > /dev/null && echo 'active'", shell=True)
        pulseaudio_info['pulseaudio_status'] = pulseaudio_check if pulseaudio_check else "Not running"
        
        # Get PulseAudio version
        pa_version = self.run_command("pactl --version 2>/dev/null", shell=True)
        pulseaudio_info['pulseaudio_version'] = pa_version if pa_version else "N/A"
        
        # Get PulseAudio sinks (output devices)
        pa_sinks = self.run_command("pactl list short sinks 2>/dev/null", shell=True)
        pulseaudio_info['pulseaudio_sinks'] = pa_sinks if pa_sinks else "N/A"
        
        # Get PulseAudio sources (input devices)
        pa_sources = self.run_command("pactl list short sources 2>/dev/null", shell=True)
        pulseaudio_info['pulseaudio_sources'] = pa_sources if pa_sources else "N/A"
        
        # Get PulseAudio configuration
        pa_info = self.run_command("pactl info 2>/dev/null", shell=True)
        pulseaudio_info['pulseaudio_info'] = pa_info if pa_info else "N/A"
        
        self.info['pulseaudio_info'] = pulseaudio_info
    
    def get_jack_info(self):
        """Get JACK (Jack Audio Connection Kit) information"""
        jack_info = OrderedDict()
        
        # Check if JACK is running
        jack_check = self.run_command("pgrep jackd > /dev/null && echo 'running' || echo 'not running'", shell=True)
        jack_info['jack_status'] = jack_check if jack_check else "N/A"
        
        # Get JACK version
        jack_version = self.run_command("jackd --version 2>/dev/null", shell=True)
        jack_info['jack_version'] = jack_version if jack_version else "N/A"
        
        # Get JACK configuration
        jack_config = self.run_command("cat ~/.jackdrc 2>/dev/null || echo 'N/A'", shell=True)
        jack_info['jack_config'] = jack_config if jack_config else "N/A"
        
        self.info['jack_info'] = jack_info
    
    def get_audio_kernel_modules(self):
        """Get loaded audio kernel modules"""
        kernel_modules = OrderedDict()
        
        # Get ALSA modules
        alsa_modules = self.run_command("lsmod | grep -E 'snd_|soundcore|dsp'", shell=True)
        kernel_modules['alsa_modules'] = alsa_modules if alsa_modules else "Not loaded"
        
        # Get specific codec modules
        codec_modules = self.run_command("lsmod | grep -i 'codec'", shell=True)
        kernel_modules['codec_modules'] = codec_modules if codec_modules else "Not loaded"
        
        # Get HDA Intel (High Definition Audio)
        hda_modules = self.run_command("lsmod | grep -i 'snd_hda'", shell=True)
        kernel_modules['hda_modules'] = hda_modules if hda_modules else "Not loaded"
        
        # Get USB audio modules
        usb_audio = self.run_command("lsmod | grep -i 'usb.*audio\\|snd_usb'", shell=True)
        kernel_modules['usb_audio_modules'] = usb_audio if usb_audio else "Not loaded"
        
        # Get ES1371 (VMware audio device)
        es1371 = self.run_command("lsmod | grep -i 'es1371\\|ensoniq'", shell=True)
        kernel_modules['es1371_module'] = es1371 if es1371 else "Not loaded"
        
        self.info['audio_kernel_modules'] = kernel_modules
    
    def get_vmware_audio_info(self):
        """Get VMware-specific audio information"""
        vmware_audio = OrderedDict()
        
        if self.is_vmware:
            vmware_audio['virtualization_type'] = "VMware"
            
            # Check for ES1371 device
            es1371_device = self.run_command("lspci | grep -i 'es1371\\|ensoniq'", shell=True)
            vmware_audio['es1371_device'] = es1371_device if es1371_device else "Not found"
            
            # Check ES1371 detailed info
            es1371_detailed = self.run_command("lspci -k | grep -A 3 -i 'es1371\\|ensoniq'", shell=True)
            vmware_audio['es1371_detailed'] = es1371_detailed if es1371_detailed else "N/A"
            
            # Check dmesg for audio initialization
            dmesg_audio = self.run_command("dmesg | grep -i 'es1371\\|ensoniq\\|audio' | head -5", shell=True)
            vmware_audio['vmware_audio_boot_info'] = dmesg_audio if dmesg_audio else "N/A"
            
            # Check if audio device is disabled in BIOS/VM settings
            audio_disabled = self.run_command("lspci | grep -i 'es1371\\|ensoniq' && echo 'Enabled' || echo 'Disabled'", shell=True)
            vmware_audio['audio_device_status'] = audio_disabled if audio_disabled else "Unknown"
        else:
            vmware_audio['virtualization_type'] = "Physical Server or Non-VMware VM"
            vmware_audio['es1371_device'] = "N/A"
            vmware_audio['es1371_detailed'] = "N/A"
            vmware_audio['vmware_audio_boot_info'] = "N/A"
        
        self.info['vmware_audio_info'] = vmware_audio
    
    def get_audio_subsystem_info(self):
        """Get audio subsystem information"""
        subsystem_info = OrderedDict()
        
        # Get hwmon audio devices
        hwmon_audio = self.run_command("ls /sys/class/sound/ 2>/dev/null", shell=True)
        subsystem_info['sound_devices_sysfs'] = hwmon_audio if hwmon_audio else "N/A"
        
        # Get audio device permissions
        audio_perms = self.run_command("ls -la /dev/snd/ 2>/dev/null | head -20", shell=True)
        subsystem_info['audio_device_permissions'] = audio_perms if audio_perms else "N/A"
        
        self.info['audio_subsystem_info'] = subsystem_info
    
    def get_audio_server_status(self):
        """Get audio server status"""
        server_status = OrderedDict()
        
        # Check systemd audio services
        audio_services = self.run_command("systemctl list-units --type=service | grep -i 'audio\\|sound\\|pulse\\|jack'", shell=True)
        server_status['audio_services'] = audio_services if audio_services else "N/A"
        
        # Check if audio daemon is running
        audio_daemon = self.run_command("ps aux | grep -i 'pulseaudio\\|jackd\\|alsa' | grep -v grep", shell=True)
        server_status['audio_daemons'] = audio_daemon if audio_daemon else "N/A"
        
        self.info['audio_server_status'] = server_status
    
    def get_audio_file_support(self):
        """Get audio file format support"""
        file_support = OrderedDict()
        
        # Check ffmpeg support
        ffmpeg_check = self.run_command("which ffmpeg", shell=True)
        if ffmpeg_check:
            ffmpeg_codecs = self.run_command("ffmpeg -codecs 2>&1 | grep -i 'audio' | head -10", shell=True)
            file_support['ffmpeg_audio_codecs'] = ffmpeg_codecs if ffmpeg_codecs else "N/A"
        else:
            file_support['ffmpeg_audio_codecs'] = "ffmpeg not installed"
        
        # Check sox (Sound eXchange)
        sox_check = self.run_command("which sox", shell=True)
        if sox_check:
            sox_info = self.run_command("sox --version", shell=True)
            file_support['sox_version'] = sox_info if sox_info else "N/A"
        else:
            file_support['sox_version'] = "sox not installed"
        
        self.info['audio_file_support'] = file_support
    
    def get_dmesg_audio_info(self):
        """Get audio information from dmesg"""
        dmesg_audio = self.run_command("dmesg | grep -i 'audio\\|sound\\|snd_\\|alsa\\|codec' | tail -20", shell=True)
        self.info['dmesg_audio_info'] = dmesg_audio if dmesg_audio else "N/A"
    
    def get_audio_configuration_files(self):
        """Get audio configuration files"""
        config_files = OrderedDict()
        
        # Get ALSA config
        alsa_conf = self.run_command("cat /etc/asound.conf 2>/dev/null | head -30", shell=True)
        config_files['alsa_config'] = alsa_conf if alsa_conf else "N/A"
        
        # Get PulseAudio config
        pa_conf = self.run_command("cat ~/.config/pulse/default.pa 2>/dev/null | head -30", shell=True)
        config_files['pulseaudio_config'] = pa_conf if pa_conf else "N/A"
        
        self.info['audio_config_files'] = config_files
    
    def gather_all_info(self):
        """Collect all audio device information"""
        print("[*] Gathering audio device information...")
        
        self.get_vmware_audio_info()
        print("    [+] VMware/Virtualization audio detection - OK")
        
        self.get_audio_devices_pci()
        print("    [+] Audio devices (PCI) - OK")
        
        self.get_alsa_info()
        print("    [+] ALSA info - OK")
        
        self.get_pulseaudio_info()
        print("    [+] PulseAudio info - OK")
        
        self.get_jack_info()
        print("    [+] JACK info - OK")
        
        self.get_audio_kernel_modules()
        print("    [+] Audio kernel modules - OK")
        
        self.get_audio_subsystem_info()
        print("    [+] Audio subsystem info - OK")
        
        self.get_audio_server_status()
        print("    [+] Audio server status - OK")
        
        self.get_audio_file_support()
        print("    [+] Audio file support - OK")
        
        self.get_audio_configuration_files()
        print("    [+] Audio configuration files - OK")
        
        self.get_dmesg_audio_info()
        print("    [+] dmesg audio info - OK")
        
        print("[*] Information gathering completed!\n")
    
    def get_info(self, key=None):
        """Return information"""
        if key is None:
            return self.info
        return self.info.get(key, "N/A")
    
    def display_info(self, verbose=True):
        """Display collected information"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " AUDIO INFORMATIONS REPORT ".center(78) + "║")
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
    crawler = AudioCrawler()
    crawler.gather_all_info()
    crawler.display_info(verbose=True)
    
    return crawler


if __name__ == "__main__":
    main()