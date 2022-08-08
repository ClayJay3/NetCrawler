# Import required packages and modules.
from ast import Tuple
from functools import partial
import re
import logging
from multiprocessing.pool import ThreadPool
from netmiko import NetmikoAuthenticationException
from netmiko.ssh_dispatcher import ConnectHandler

# Define Constants.
MAX_DISCOVERY_THREADS = 100

# Create global file variables.
ip_discovery_list = []
export_info_list = []

def cdp_auto_discover(ip_list, username, password, export_info=False) -> list:
    """
    This function takes in a list of strings containing the ip addresses to start auto discovery with.
    Then new processes are spawned that run a show cdp neighbors command and parse the output to find more connected switches.
    Those new switches then go through the same process until no more switches are discoverd.

    This method is recursive.

    Parameters:
    -----------
        list(string) - A list of the initially known switch IPs.

    Returns:
    --------
        list(string) - A list of strings containg the new switch IPs. Duplicated are removed.
    """
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)

    # Check if length of IP list is greater than zero.
    if len(ip_list) == 0:
        # Print log.
        logger.info("Discovery has reached the end of the network, closing recursive branches now.")
        # Return if we hit the end of the switch line.
        return ip_discovery_list, export_info_list
    else:
        # Create a new thread pool and get cdp info.
        pool = ThreadPool(MAX_DISCOVERY_THREADS)
        # Loop through each ip and create a new thread to get info.
        result_ips = pool.map_async(partial(get_cdp_neighbors_info, username, password, export_info), ip_list)
        # Wait for pool threads to finish.
        pool.close()
        pool.join()

        # Get resulting IPs and filter out duplicates.
        new_ips = []
        for discovered_ip_addrs, device_infos in result_ips.get():
            for ip_addr in discovered_ip_addrs:
                if not ip_addr in ip_discovery_list:
                    # Append them to discover list. Also create a new list with this recursion layers new unique IPs.
                    ip_discovery_list.append(ip_addr)
                    new_ips.append(ip_addr)
            for info in device_infos:
                # Add device info to info list if not already there.
                if export_info and len(info) > 0 and info["hostname"] != "NULL" and not info in export_info_list:
                    # Use list comprehension to check of the hostname has already been put into the dictionary list.
                    hostnames = [key_val["hostname"] for key_val in export_info_list]
                    if info["hostname"] not in hostnames:
                        # Finally, append to list.
                        export_info_list.append(info)

        # Print log.
        logger.info(f"Discovered IPs {new_ips} from the following devices: {ip_list}")

        # Recursion baby.
        return cdp_auto_discover(new_ips, username, password, export_info)

def get_cdp_neighbors_info(usernames, passwords, export_info, ip_addr) -> Tuple(list):
    """
    This function opens a new ssh connection with the given ip and gets cdp neighbors info.

    Parameters:
    -----------
        ip_addr - The IP address of the switch.
        usernames - The login username list
        passwords - The login password list

    Returns:
    --------
        list - A list containing the connected cdp devices IP info.
        device_info - A list containing other device info.
    """
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    cdp_neighbors_result_ips = []
    device_infos = []

    for username, password in zip(usernames, passwords):
        # Create device dictionary.
        remote_device = {"device_type": "autodetect", "host": ip_addr, "username": username, "password": password}
        # If the device is not a switch codemiko will crash.
        try:
            # Open new ssh connection with switch.
            ssh_connection = ConnectHandler(**remote_device)
            # Get parent hostname.
            prompt = ssh_connection.find_prompt()[:-1]

            #######################################################################
            # Get the IP and hostname info.
            #######################################################################
            # Run cdp command to get relavant info.
            output = ssh_connection.send_command("show cdp neighbors detail | sec Device|Management|Capabilities|Version|Interface")

            # Parse output, split string based on the Device keyword.
            device_cdps = re.split("Device", output)
            # Loop through device strings.
            for device in device_cdps:
                # Split lines.
                info = device.splitlines()

                # Create device info variables.
                device_info = {}
                hostname = "NULL"
                addr = "NULL"
                local_trunk_interface = "NULL"
                software_name = "NULL"
                version = "NULL"
                platform = "NULL"
                is_wireless_ap = False
                is_switch = True
                is_phone = False
                parent_addr = "NULL"
                parent_host = "NULL"
                parent_trunk_interface = "NULL"
                # Loop through each line and find the device info.
                for line in info:
                    # Find device IP address.
                    if "IP address:" in line:
                        # Replace keyword.
                        addr = line.replace("IP address: ", "").strip()
                    # Find device type:
                    if "AIR" in line or "Trans-Bridge" in line:
                        is_wireless_ap = True
                        is_switch = False
                    # Check if export info is toggled on.
                    if export_info and len(addr) > 0 and not is_wireless_ap:
                        # Find device hostname.
                        if "ID:" in line:
                            # Replace keyword.
                            line = line.replace("ID:", "")
                            # Remove whitespace and store data.
                            hostname = line.strip()

                        # Find device software version info.
                        if "Version :" not in line and "Version" in line:
                            # Split line up by commas.
                            line = re.split(",", line)
                            # Loop through and find software name and version.
                            for i, section in enumerate(line):
                                # First line will be the software name.
                                if i == 0:
                                    software_name = section
                                # Find version.
                                if "Version" in section:
                                    # Remove keyword.
                                    section = section.replace("Version", "")
                                    # Strip whitespace and store.
                                    version = section.strip()

                        # Find platform.
                        if "Platform" in line:
                            # Remove keyword and other garbage after the comma
                            line = line.replace("Platform:", "")
                            line = line.split(",", 1)[0]
                            # Remove whitespace and store.
                            platform = line.strip()

                        # Find the local trunk interface and parent interface.
                        if "Interface:" in line:
                            # Split line by comma.
                            line = re.split(",", line)
                            # Get and store the local and remote interface.
                            remote_interface = line[0]
                            local_interface = line[1]
                            # Remove unessesary keyword arguments.
                            remote_interface = remote_interface.replace("Interface:", "")
                            local_interface = local_interface.replace("Port ID (outgoing port):", "")
                            # Remove whitespace and store.
                            local_trunk_interface = local_interface.strip()
                            parent_trunk_interface = remote_interface.strip()

                # If both the software name and version were unable to be found assume device is not a switch, but a phone.
                if export_info:
                    if software_name == "NULL" and version == "NULL":
                        is_switch = False
                        # If platform is null, then it's not a phone.
                        if platform != "NULL" and platform != "Linux":
                            is_phone = True

                    # Append parent address to device.
                    parent_addr = ip_addr
                    parent_host = prompt

                # Add info to dictionary.
                device_info["hostname"] = hostname
                device_info["ip_addr"] = addr
                device_info["local_trunk_interface"] = local_trunk_interface
                device_info["software_name"] = software_name
                device_info["version"] = version
                device_info["platform"] = platform
                device_info["is_wireless_ap"] = is_wireless_ap
                device_info["is_switch"] = is_switch
                device_info["is_phone"] = is_phone
                device_info["parent_addr"] = parent_addr
                device_info["parent_host"] = parent_host
                device_info["parent_trunk_interface"] = parent_trunk_interface

                # Remove leading whitespace and append final ip to the cdp info list.
                if addr != "NULL" and is_switch:
                    cdp_neighbors_result_ips.append(addr)

                # Append device to the device infos list.
                if export_info and device_info not in device_infos:
                    device_infos.append(device_info)

            # Close ssh connection.
            ssh_connection.disconnect()

            # Stop looping through for loop.
            break
        except NetmikoAuthenticationException:
            # Print log
            logger.warning(f"Failed to login to device {ip_addr} while discovering. Trying next username and password.")
        except Exception:
            # This process needs to be fast, so minimal error handling is okay.
            pass

    return cdp_neighbors_result_ips, device_infos

def clear_discoveries() -> None:
    """
    This method clears the global lists.

    Parameters:
    -----------
        None

    Returns:
    --------
        Nothing
    """
    # Clear global lists.
    ip_discovery_list.clear()
    export_info_list.clear()
