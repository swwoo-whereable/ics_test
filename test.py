import os
import json
import logging
import subprocess
import time
import re
from datetime import datetime
from pathlib import Path
import platform
import ctypes
import ipaddress
from typing import Dict, Optional, List, Any, Tuple

# Configuration paths
CONFIG_PATH = "./ics_config.json"
LOG_PATH = "./ics_manager.log"
SSH_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")

# Colors for UI
class Colors:
    TITLE = "\033[96m"      # Cyan
    SUCCESS = "\033[92m"    # Green
    ERROR = "\033[91m"      # Red
    WARNING = "\033[93m"    # Yellow
    INFO = "\033[97m"       # White
    MENU = "\033[95m"       # Magenta
    ENDC = "\033[0m"       # Reset color

def is_administrator() -> bool:
    """Check if the script is running with administrator privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

def get_shared_adapter() -> Optional[str]:
    """Get the shared network adapter name."""
    try:
        result = subprocess.run(
            ["powershell", "Get-NetAdapter | Where-Object { $_.MacAddress -like 'A0-1E-0B*' } | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True
        )
        adapter = result.stdout.strip()
        if adapter:
            return adapter
        logging.error("Shared adapter with MAC starting with A0-1E-0B not found")
        return None
    except Exception as e:
        logging.error(f"Error getting shared adapter: {e}")
        return None

def get_wireless_adapter() -> Optional[str]:
    """Get the wireless network adapter name."""
    try:
        # Get all network adapters
        result = subprocess.run(
            ["powershell", "Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wireless*' -or $_.InterfaceDescription -like '*WiFi*' } | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True
        )
        adapter = result.stdout.strip()
        
        if not adapter:
            logging.error("Wireless adapter not found")
            return None
            
        # Check connectivity
        conn_result = subprocess.run(
            ["powershell", f"(Get-NetConnectionProfile -InterfaceAlias '{adapter}').IPv4Connectivity"],
            capture_output=True, text=True
        )
        
        if "Internet" not in conn_result.stdout:
            logging.error("Wireless adapter does not have internet connectivity")
            return None
            
        return adapter
    except Exception as e:
        logging.error(f"Error getting wireless adapter: {e}")
        return None

def setup_logging():
    """Configure logging settings."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_PATH),
            logging.StreamHandler()
        ]
    )

def write_log(message: str, color: str = Colors.INFO):
    """Write a log message with color."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    print(f"{color}{log_message}{Colors.ENDC}")
    logging.info(message)

def load_config() -> Dict:
    """Load configuration from file or create default if not exists."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    
    config = {
        "ScriptName": "set_ics.sh",
        "NetworkPrefix": "192.168",
        "AllowedSuffixes": ["137", "1", "0"],
        "Windows": {
            "User": os.getenv("USERNAME"),
            "SSHKeyPath": os.path.expanduser("~/.ssh/id_rsa")
        },
        "Devices": {
            "Device1": {
                "NormalIP": "192.168.1.41",
                "ICSIP": "192.168.137.41",
                "User": "aaeon",
                "Password": "aaeon",
                "InitialConnection": False
            },
            "Device2": {
                "NormalIP": "192.168.1.42",
                "ICSIP": "192.168.137.42",
                "User": "aaeon",
                "Password": "aaeon",
                "InitialConnection": False
            }
        }
    }
    
    save_config(config)
    return config

def save_config(config: Dict):
    """Save configuration to file."""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=4)
        write_log("Configuration saved", Colors.SUCCESS)
    except Exception as e:
        write_log(f"Failed to save configuration: {e}", Colors.ERROR)
        raise

def test_network_connection(ip: str, timeout: int = 5) -> bool:
    """Test network connectivity to an IP address."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["ping", "-n", "1", "-w", str(timeout * 1000), ip],
                                 capture_output=True, text=True)
        else:
            result = subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                                 capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def test_ssh_connection(ip: str, user: str, password: str = "", use_key: bool = True) -> bool:
    """Test SSH connection to a device."""
    write_log(f"Testing SSH connection to {ip}...")
    
    try:
        if use_key:
            if not os.path.exists(SSH_KEY_PATH):
                write_log(f"SSH key not found at {SSH_KEY_PATH}", Colors.ERROR)
                return False
            
            # Test SSH key permissions on Unix-like systems
            if platform.system() != "Windows":
                key_stat = os.stat(SSH_KEY_PATH)
                if key_stat.st_mode & 0o777 != 0o600:
                    write_log("SSH key has incorrect permissions", Colors.ERROR)
                    return False
            
            cmd = ["ssh", "-i", SSH_KEY_PATH, "-o", "ConnectTimeout=5", f"{user}@{ip}", "echo 'Connection successful'"]
        else:
            if not password:
                write_log("Password required for non-key authentication", Colors.ERROR)
                return False
            # Using sshpass for password authentication
            cmd = ["sshpass", "-p", password, "ssh", "-o", "ConnectTimeout=5", f"{user}@{ip}", "echo 'Connection successful'"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if "Connection successful" not in result.stdout:
            write_log("SSH connection test failed - unexpected response", Colors.ERROR)
            return False
        
        # Test sudo access
        if use_key:
            sudo_cmd = ["ssh", "-i", SSH_KEY_PATH, f"{user}@{ip}", "echo 'test' | sudo -S echo 'sudo test' 2>&1"]
        else:
            sudo_cmd = ["sshpass", "-p", password, "ssh", f"{user}@{ip}", f"echo '{password}' | sudo -S echo 'sudo test' 2>&1"]
        
        sudo_result = subprocess.run(sudo_cmd, capture_output=True, text=True)
        if "sudo test" not in sudo_result.stdout:
            write_log(f"User {user} does not have sudo privileges on {ip}", Colors.ERROR)
            return False
        
        return True
    except Exception as e:
        write_log(f"SSH connection error: {e}", Colors.ERROR)
        return False

def find_device_network(device_config: Dict, config: Dict) -> Optional[str]:
    """Find the network where the device is accessible."""
    shared_adapter = get_shared_adapter()
    if not shared_adapter:
        write_log("Cannot proceed without shared adapter", Colors.ERROR)
        return None
    
    # Get current Windows IP
    result = subprocess.run(
        ["powershell", f"Get-NetIPAddress -InterfaceAlias '{shared_adapter}' -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"],
        capture_output=True, text=True
    )
    current_windows_ip = result.stdout.strip()
    windows_last_segment = current_windows_ip.split('.')[-1]
    
    # Try current subnet first
    current_suffix = device_config["NormalIP"].split('.')[2]
    network_prefix = f"{config['NetworkPrefix']}.{current_suffix}"
    test_ip = f"{network_prefix}.{device_config['NormalIP'].split('.')[-1]}"
    
    write_log(f"Testing connection on current subnet to {test_ip}...", Colors.INFO)
    if test_network_connection(test_ip):
        return test_ip
    
    # Try other subnets sequentially
    for suffix in config["AllowedSuffixes"]:
        if suffix == current_suffix:
            continue
        
        network_prefix = f"{config['NetworkPrefix']}.{suffix}"
        test_ip = f"{network_prefix}.{device_config['NormalIP'].split('.')[-1]}"
        new_windows_ip = f"{network_prefix}.{windows_last_segment}"
        gateway = f"{network_prefix}.1"
        
        write_log(f"Trying subnet {suffix} - Setting Windows IP to {new_windows_ip} (Gateway: {gateway})...", Colors.INFO)
        try:
            # Remove existing IP configuration
            subprocess.run(["powershell", f"Remove-NetIPAddress -InterfaceAlias '{shared_adapter}' -AddressFamily IPv4 -Confirm:$false"],
                         check=True)
            subprocess.run(["powershell", f"Remove-NetRoute -InterfaceAlias '{shared_adapter}' -AddressFamily IPv4 -Confirm:$false"],
                         check=True)
            
            # Set new IP configuration
            subprocess.run(["powershell", 
                          f"New-NetIPAddress -InterfaceAlias '{shared_adapter}' -IPAddress '{new_windows_ip}' " +
                          f"-PrefixLength 24 -DefaultGateway '{gateway}'"],
                         check=True)
        except subprocess.CalledProcessError as e:
            write_log(f"IP change error: {e}", Colors.WARNING)
            continue
        
        time.sleep(2)
        
        if test_network_connection(test_ip):
            return test_ip
    
    return None

def generate_ssh_key():
    """Generate SSH key pair."""
    write_log("Generating SSH key...", Colors.INFO)
    ssh_dir = os.path.dirname(SSH_KEY_PATH)
    
    # Create .ssh directory if it doesn't exist
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir, mode=0o700)
    
    # Generate key
    try:
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", SSH_KEY_PATH, "-N", ""], check=True)
        
        if not os.path.exists(SSH_KEY_PATH):
            raise Exception("SSH key file not created")
        
        # Set correct permissions
        if platform.system() != "Windows":
            os.chmod(SSH_KEY_PATH, 0o600)
            os.chmod(SSH_KEY_PATH + ".pub", 0o644)
        
        write_log("SSH key generated successfully", Colors.SUCCESS)
    except Exception as e:
        write_log(f"Failed to generate SSH key: {e}", Colors.ERROR)
        raise

def initialize_device_connection(config: Dict) -> bool:
    """Initialize connections to all devices."""
    devices_modified = False
    
    for device_name, device_config in config["Devices"].items():
        if not device_config["InitialConnection"]:
            write_log(f"Initializing connection for device at {device_config['NormalIP']}...", Colors.INFO)
            
            current_ip = find_device_network(device_config, config)
            if not current_ip:
                write_log("Could not find device on any network", Colors.ERROR)
                continue
            
            # Try SSH key first if exists
            if os.path.exists(SSH_KEY_PATH):
                if test_ssh_connection(current_ip, device_config["User"], use_key=True):
                    write_log("Connected successfully using SSH key", Colors.SUCCESS)
                    device_config["InitialConnection"] = True
                    devices_modified = True
                    continue
            
            # Try password authentication
            if test_ssh_connection(current_ip, device_config["User"], device_config["Password"], use_key=False):
                write_log("Connected successfully using password", Colors.SUCCESS)
                
                # Generate and copy SSH key if it doesn't exist
                if not os.path.exists(SSH_KEY_PATH):
                    generate_ssh_key()
                
                # Copy SSH key to device
                try:
                    with open(f"{SSH_KEY_PATH}.pub", 'r') as f:
                        key_content = f.read().strip()
                    
                    if not key_content:
                        write_log("Failed to read public key content", Colors.ERROR)
                        continue
                    
                    command = f"mkdir -p ~/.ssh && echo '{key_content}' >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
                    subprocess.run(["sshpass", "-p", device_config["Password"], 
                                  "ssh", f"{device_config['User']}@{current_ip}", command],
                                 check=True)
                    
                    # Verify key was copied correctly
                    if not test_ssh_connection(current_ip, device_config["User"], use_key=True):
                        write_log("SSH key verification failed after copying", Colors.ERROR)
                        continue
                    
                    device_config["InitialConnection"] = True
                    devices_modified = True
                except Exception as e:
                    write_log(f"Failed to copy SSH key: {e}", Colors.ERROR)
                    continue
            else:
                write_log(f"Failed to connect to device at {current_ip}", Colors.ERROR)
    
    if devices_modified:
        save_config(config)
    
    return devices_modified

def show_header():
    """Display the program header."""
    print(f"\n{Colors.TITLE}=== ICS Manager Tool ==={Colors.ENDC}")
    print(f"{Colors.INFO}Network Configuration Tool for Linux Devices\n{Colors.ENDC}")

def show_config_menu(config: Dict):
    """Display and handle the configuration menu."""
    print(f"\n{Colors.TITLE}Current Configuration:{Colors.ENDC}")
    print(f"Script Name: {config['ScriptName']}")
    
    for device_name, device in config["Devices"].items():
        print(f"\nDevice: {device_name}")
        print(f"Normal IP: {device['NormalIP']}")
        print(f"ICS IP: {device['ICSIP']}")
    
    print("\n1. Change Script Name")
    print("2. Change Device Normal IP")
    print("3. Change Device ICS IP")
    print("4. Back")
    
    choice = input("\nSelect option (1-4): ")
    
    if choice == "1":
        config["ScriptName"] = input("Enter new script name (Example: set_ics.sh): ")
        save_config(config)
    
    elif choice == "2":
        device_name = input("Enter device name (Device1/Device2): ")
        if device_name not in config["Devices"]:
            write_log("Invalid device name", Colors.ERROR)
            return
        
        new_ip = input("Enter Normal IP: ")
        try:
            ipaddress.ip_address(new_ip)  # Validate IP format
            config["Devices"][device_name]["NormalIP"] = new_ip
            save_config(config)
        except ValueError:
            write_log("Invalid IP format", Colors.ERROR)
    
    elif choice == "3":
        device_name = input("Enter device name (Device1/Device2): ")
        if device_name not in config["Devices"]:
            write_log("Invalid device name", Colors.ERROR)
            return
        
        new_ip = input("Enter ICS IP: ")
        try:
            ipaddress.ip_address(new_ip)  # Validate IP format
            config["Devices"][device_name]["ICSIP"] = new_ip
            save_config(config)
        except ValueError:
            write_log("Invalid IP format", Colors.ERROR)
    
    elif choice != "4":
        write_log("Invalid option", Colors.WARNING)

def show_menu():
    """Display the main menu."""
    print("1. Enable ICS")
    print("2. Disable ICS")
    print("3. Configure Settings")
    print("4. Exit")
    return input("\nSelect option (1-4): ")

def test_internet_connection() -> bool:
    """Test internet connectivity."""
    result = test_network_connection("8.8.8.8")
    if not result:
        write_log("No internet connection available", Colors.ERROR)
    return result

def execute_ssh_command(ip: str, user: str, command: str, use_key: bool = True, password: str = "") -> Optional[str]:
    """Execute an SSH command on a remote device."""
    try:
        if use_key:
            if not os.path.exists(SSH_KEY_PATH):
                raise Exception("SSH key not found")
            cmd = ["ssh", "-i", SSH_KEY_PATH, f"{user}@{ip}", command]
        else:
            if not password:
                raise Exception("Password is required when not using SSH key")
            cmd = ["sshpass", "-p", password, "ssh", f"{user}@{ip}", command]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception as e:
        write_log(f"SSH command failed: {e}", Colors.ERROR)
        return None

def get_linux_interface(ip: str, user: str) -> Optional[str]:
    """Get the network interface name on Linux device."""
    command = "ip link show | grep -B 1 '00:07:32' | head -n 1 | awk -F: '{print $2}' | tr -d ' '"
    interface = execute_ssh_command(ip, user, command)
    if not interface:
        write_log("Failed to get Linux interface name", Colors.ERROR)
        return None
    return interface

def copy_script_to_target(ip: str, user: str, config: Dict) -> bool:
    """Copy the ICS script to target device."""
    try:
        write_log("Checking if script exists on target...")
        if not os.path.exists(config["ScriptName"]):
            write_log(f"Script file not found locally: {config['ScriptName']}", Colors.ERROR)
            return False
        
        # Check if script exists on target
        check_cmd = f"test -f ~/{config['ScriptName']} && echo 'exists'"
        script_exists = execute_ssh_command(ip, user, check_cmd, use_key=True)
        
        if script_exists != "exists":
            write_log("Copying script to target...")
            # Copy script
            result = subprocess.run(["scp", "-i", SSH_KEY_PATH, config["ScriptName"], f"{user}@{ip}:~/"],
                                 capture_output=True, text=True)
            if result.returncode != 0:
                write_log("Failed to copy script", Colors.ERROR)
                return False
            write_log("Script copied successfully", Colors.SUCCESS)
            
            # Set executable permission
            chmod_cmd = f"chmod +x ~/{config['ScriptName']}"
            result = execute_ssh_command(ip, user, chmod_cmd, use_key=True)
            if result is None:
                write_log("Failed to set executable permission for script", Colors.ERROR)
                return False
            write_log("Set executable permission for script", Colors.SUCCESS)
        else:
            write_log("Script already exists on target", Colors.INFO)
        
        return True
    except Exception as e:
        write_log(f"Error copying script: {e}", Colors.ERROR)
        return False
    
def set_ics_configuration(enable: bool) -> bool:
    """Configure Internet Connection Sharing (ICS)."""
    try:
        write_log("Checking ICS status...")
        
        source_adapter = get_wireless_adapter()
        dest_adapter = get_shared_adapter()
        
        if not source_adapter or not dest_adapter:
            write_log("Required network adapters not found", Colors.ERROR)
            return False

        # Using PowerShell to manage ICS
        ps_script = f"""
        $netShare = New-Object -ComObject HNetCfg.HNetShare
        $connection = $netShare.EnumEveryConnection | Where-Object {{
            $netShare.NetConnectionProps.Invoke($_).Name -eq '{source_adapter}'
        }}
        if ($connection) {{
            $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($connection)
            $currentStatus = $config.SharingEnabled
            if ({str(enable).lower()}) {{
                if ($currentStatus) {{
                    $config.DisableSharing()
                    Start-Sleep -Seconds 2
                    $config.EnableSharing(1)
                }} else {{
                    $config.EnableSharing(1)
                }}
            }} else {{
                if ($currentStatus) {{
                    $config.DisableSharing()
                }}
            }}
            Write-Output "Success"
        }} else {{
            Write-Error "Source adapter not found"
        }}
        """
        
        result = subprocess.run(["powershell", "-Command", ps_script], 
                              capture_output=True, text=True)
        
        if "Success" not in result.stdout:
            write_log(f"Failed to configure ICS: {result.stderr}", Colors.ERROR)
            return False
        
        if not enable:
            # Reset Windows IP configuration to normal network
            shared_adapter = get_shared_adapter()
            device_config = next(iter(config["Devices"].values()))
            network_prefix = ".".join(device_config["NormalIP"].split(".")[:3])
            
            result = subprocess.run(
                ["powershell", f"Get-NetIPAddress -InterfaceAlias '{shared_adapter}' -AddressFamily IPv4"],
                capture_output=True, text=True
            )
            windows_last_segment = result.stdout.strip().split(".")[-1]
            
            new_windows_ip = f"{network_prefix}.{windows_last_segment}"
            gateway = f"{network_prefix}.1"
            
            try:
                subprocess.run(["powershell", f"Remove-NetIPAddress -InterfaceAlias '{shared_adapter}' -AddressFamily IPv4 -Confirm:$false"],
                             check=True)
                subprocess.run(["powershell", f"Remove-NetRoute -InterfaceAlias '{shared_adapter}' -AddressFamily IPv4 -Confirm:$false"],
                             check=True)
                subprocess.run(["powershell", 
                              f"New-NetIPAddress -InterfaceAlias '{shared_adapter}' -IPAddress '{new_windows_ip}' " +
                              f"-PrefixLength 24 -DefaultGateway '{gateway}'"],
                             check=True)
                write_log("Windows IP configuration updated", Colors.SUCCESS)
            except subprocess.CalledProcessError as e:
                write_log(f"Failed to update Windows IP configuration: {e}", Colors.ERROR)
                return False
        
        write_log(f"ICS {'enabled' if enable else 'disabled'} successfully", Colors.SUCCESS)
        return True
    
    except Exception as e:
        write_log(f"Error configuring ICS: {e}", Colors.ERROR)
        return False

def execute_ics_command(enable: bool, config: Dict):
    """Execute ICS enable/disable command for all devices."""
    if not config["Devices"]:
        write_log("No devices configured", Colors.ERROR)
        return

    if not test_internet_connection():
        write_log("No internet connectivity detected. Cannot proceed.", Colors.ERROR)
        return

    action = "enable" if enable else "disable"
    write_log(f"Executing {action} command for all devices...")

    device_configurations = []

    for device_name, device_config in config["Devices"].items():
        current_ip = device_config["NormalIP"] if enable else device_config["ICSIP"]
        expected_ip = device_config["ICSIP"] if enable else device_config["NormalIP"]
        
        write_log(f"Processing device: {device_name}", Colors.INFO)
        
        if not test_network_connection(current_ip):
            write_log(f"Cannot reach device at {current_ip}, searching on other networks...", Colors.WARNING)
            current_ip = find_device_network(device_config, config)
            
            if not current_ip:
                write_log(f"Cannot find device {device_name} on any network", Colors.ERROR)
                return
        
        if not test_ssh_connection(current_ip, device_config["User"], use_key=True):
            write_log(f"Cannot connect to device at {current_ip}", Colors.ERROR)
            return
        
        if not copy_script_to_target(current_ip, device_config["User"], config):
            write_log("Failed to prepare script on target device", Colors.ERROR)
            return
        
        write_log(f"Configuring Linux network for {device_name}...")
        command = "137" if enable else "1"
        result = execute_ssh_command(current_ip, device_config["User"], 
                                   f"sudo bash ~/{config['ScriptName']} {command}")
        if result is None:
            write_log("Failed to execute network configuration script", Colors.ERROR)
            return
        
        write_log(result, Colors.SUCCESS)
        write_log("Waiting for Linux network configuration...")
        time.sleep(5)
        
        device_configurations.append({
            "Name": device_name,
            "Config": device_config,
            "ExpectedIP": expected_ip
        })
    
    if set_ics_configuration(enable):
        write_log("Windows ICS configuration completed", Colors.SUCCESS)
        write_log("Verifying final configuration...")
        time.sleep(5)
        
        all_success = True
        for device in device_configurations:
            retry_count = 0
            max_retries = 3
            success = False
            
            while retry_count < max_retries and not success:
                write_log(f"Attempting to connect to {device['Name']} at {device['ExpectedIP']}... Attempt {retry_count + 1}")
                if test_ssh_connection(device['ExpectedIP'], device['Config']['User'], use_key=True):
                    interface = get_linux_interface(device['ExpectedIP'], device['Config']['User'])
                    if interface:
                        new_config = execute_ssh_command(device['ExpectedIP'], 
                                                       device['Config']['User'],
                                                       f"ifconfig {interface} | grep 'inet '")
                        if new_config:
                            write_log(f"{device['Name']} new IP configuration: {new_config}", Colors.SUCCESS)
                            success = True
                
                if not success:
                    retry_count += 1
                    if retry_count < max_retries:
                        write_log("Connection failed, retrying...", Colors.WARNING)
                        time.sleep(2)
            
            if not success:
                write_log(f"Failed to verify new configuration for {device['Name']}", Colors.ERROR)
                all_success = False
        
        if not all_success:
            write_log("Some devices failed to configure properly", Colors.ERROR)
    else:
        write_log("Failed to configure Windows ICS", Colors.ERROR)
    
    input("\nPress Enter to continue...")

def main():
    """Main execution function."""
    try:
        if not is_administrator():
            write_log("This script requires administrator privileges", Colors.ERROR)
            return 1

        if not test_internet_connection():
            return 1

        setup_logging()
        config = load_config()
        write_log("Program started")
        initialize_device_connection(config)

        while True:
            show_header()
            choice = show_menu()
            
            if choice == "1":
                write_log("Enabling ICS...")
                execute_ics_command(True, config)
            elif choice == "2":
                write_log("Disabling ICS...")
                execute_ics_command(False, config)
            elif choice == "3":
                show_config_menu(config)
            elif choice == "4":
                write_log("Program terminated")
                return 0
            else:
                write_log("Invalid option", Colors.WARNING)
                time.sleep(1)

    except Exception as e:
        write_log(f"Fatal error: {e}", Colors.ERROR)
        return 1

if __name__ == "__main__":
    exit(main())
