import re
import logging
import time
import subprocess
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from threading import Thread
from typing import Tuple
import netmiko

from interface.popup_window import ListPopup, MultipleListPopup, text_popup
from utils.open_connection import get_config_info, ssh_autodetect_switchlist_info, ssh


# Create Configure UI window class.
class ConfigureUI:
    """
    Class that serves as frontend for all of the individual switch configure.
    """
    def __init__(self) -> None:
        # Create class variables, objects, and constants.
        self.logger = logging.getLogger(__name__)
        self.window = None
        self.window_is_open = False
        self.window_is_initialized = False
        self.is_enabled = True
        self.retrieving_devices = False
        self.grid_size = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.font = "antiqueolive"

        # Window Frames.
        self.selector_frame = None
        self.command_button_frame = None
        self.interface_frame = None
        self.vlan_frame = None
        self.upload_frame = None

        # Window elements and objects.
        self.usernames = None
        self.passwords = None
        self.ip_list = []
        self.ssh_connections = []
        self.devices = []
        self.switch_selection = None
        self.drop_down = None
        self.interfaces_list = []
        self.interface_selection = None
        self.interface_drop_down = None
        self.interface_range_selection = None
        self.interface_range_drop_down = None
        self.interface_description_box = None
        self.int_shutdown_check = None
        self.sw_mo_acc_check = None
        self.spantree_portfast_check = None
        self.spantree_bpduguard_check = None
        self.sw_mo_trunk_check = None
        self.vlan_shutdown_check = None
        self.access_vlan_box = None
        self.voice_vlan_box = None
        self.spantree_portfast = None
        self.spantree_bpduguard = None
        self.trunk_vlan_box = None
        self.vlans_list = []
        self.vlan_selection = None
        self.vlan_drop_down = None
        self.vlan_description_box = None
        self.vlan_ipaddr_box = None
        self.text_box = None

        # This serves as a temp var used by many things, anytime a popup window that is destroyable is made, it's stored here.
        self.popup = None

    def run(self, ips, usernames, passwords) -> None:
        """
        Call this function to start UI window in a new thread.
        """
        # Set ip list var.
        self.ip_list = ips
        # Set username and password var.
        self.usernames = usernames
        self.passwords = passwords
        # Set window is open.
        self.window_is_open = True

    def initialize_window(self) -> None:
        """
        Creates and populates all MainUI windows and components.

        Parameters:
        -----------
            ips - The list containing ip and hostname status of each devices.

        Returns:
        --------
            Nothing
        """
        # Print logger info.
        self.logger.info("Initializing configuration window...")

        # Create new tk window.
        self.window = tk.Tk()
        # Set window closing actions.
        self.window.protocol("WM_DELETE_WINDOW", self.close_window)
        # Set window title.
        self.window.title("Switch Config")
        # Set window to the front of others.
        self.window.attributes("-topmost", True)
        self.window.update()
        self.window.attributes("-topmost", False)

        # Set window variables.
        self.switch_selection = tk.StringVar(self.window)
        self.switch_selection.set("No switch is selected")
        self.interface_selection = tk.StringVar(self.window)
        self.interface_selection.set("No interface is selected")
        self.interface_range_selection = tk.StringVar(self.window)
        self.interface_range_selection.set("No interface is selected")
        self.vlan_selection = tk.StringVar(self.window)
        self.vlan_selection.set("No vlan is selected")
        self.int_shutdown_check = tk.BooleanVar(self.window)
        self.sw_mo_acc_check = tk.BooleanVar(self.window)
        self.spantree_portfast_check = tk.BooleanVar(self.window)
        self.spantree_bpduguard_check = tk.BooleanVar(self.window)
        self.sw_mo_trunk_check = tk.BooleanVar(self.window)
        self.vlan_shutdown_check = tk.BooleanVar(self.window)

        # Setup window grid layout.
        self.window.rowconfigure(self.grid_size, weight=1, minsize=60)
        self.window.columnconfigure(self.grid_size, weight=1, minsize=70)

        #######################################################################
        #               Create window components.
        #######################################################################
        # Create frame for selecting which switch to connect to.
        self.selector_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        self.selector_frame.grid(row=0, column=0, columnspan=5, sticky=tk.NSEW)
        self.selector_frame.rowconfigure(self.grid_size, weight=1)
        self.selector_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for the quick command buttons.
        self.command_button_frame = tk.LabelFrame(master=self.window, text="Quick Commands", relief=tk.GROOVE, borderwidth=3)
        self.command_button_frame.grid(row=0, column=5, columnspan=5, sticky=tk.NSEW)
        self.command_button_frame.rowconfigure([0, 1], weight=1)
        self.command_button_frame.columnconfigure([0, 1, 2, 3, 4], weight=1)
        # Create frame for interface configuration.
        self.interface_frame = tk.LabelFrame(master=self.window, text="Interface Config", relief=tk.GROOVE, borderwidth=3)
        self.interface_frame.grid(row=1, rowspan=6, column=0, columnspan=4, sticky=tk.NSEW)
        self.interface_frame.rowconfigure(self.grid_size, weight=1)
        self.interface_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for vlan configuration.
        self.vlan_frame = tk.LabelFrame(master=self.window, text="VLAN Config", relief=tk.GROOVE, borderwidth=3)
        self.vlan_frame.grid(row=7, rowspan=3, column=0, columnspan=4, sticky=tk.NSEW)
        self.vlan_frame.rowconfigure(self.grid_size, weight=1)
        self.vlan_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for uploading configuration.
        self.upload_frame = tk.LabelFrame(master=self.window, text="Upload Config", relief=tk.GROOVE, borderwidth=3)
        self.upload_frame.grid(row=1, rowspan=9, column=4, columnspan=6, sticky=tk.NSEW)
        self.upload_frame.rowconfigure(0, weight=1)
        self.upload_frame.columnconfigure(0, weight=1)

        # Populate selector frame.
        write_button = tk.Button(master=self.selector_frame,  text="REFRESH", foreground="black", background="white", command=self.refresh_config_callback)
        write_button.grid(row=0, rowspan=10, column=0, columnspan=1, sticky=tk.NSEW)
        write_button = tk.Button(master=self.selector_frame,  text="WRITE", foreground="black", background="white", command=self.write_config_callback)
        write_button.grid(row=0, rowspan=10, column=1, columnspan=1, sticky=tk.NSEW)
        self.drop_down = ttk.Combobox(master=self.selector_frame, textvariable=self.switch_selection, values=self.ip_list)
        self.drop_down.bind('<<ComboboxSelected>>', self.drop_down_callback)        # Set callback binding for combobox cause it's odd.
        self.drop_down.grid(row=0, rowspan=10, column=2, columnspan=9, sticky=tk.NSEW)

        # Populate quick command frame.
        int_stat_button = tk.Button(master=self.command_button_frame,  text="Interface Status", foreground="black", background="white", command=self.interface_status_callback)
        int_stat_button.grid(row=0, column=0, columnspan=1, sticky=tk.NSEW)
        log_button = tk.Button(master=self.command_button_frame,  text="Show Log", foreground="black", background="white", command=self.show_log_callback)
        log_button.grid(row=0, column=1, sticky=tk.NSEW)
        test_link_button = tk.Button(master=self.command_button_frame,  text="Test Port Link Quality", foreground="black", background="white", command=self.test_port_link_callback)
        test_link_button.grid(row=0, column=2, columnspan=1, sticky=tk.NSEW)
        show_int_err_button = tk.Button(master=self.command_button_frame,  text="Show Interface Errors", foreground="black", background="white", command=self.show_interface_errors_callback)
        show_int_err_button.grid(row=0, column=3, columnspan=1, sticky=tk.NSEW)
        clr_int_err_button = tk.Button(master=self.command_button_frame,  text="Clear Interface Errors", foreground="black", background="white", command=self.clear_interface_errors_callback)
        clr_int_err_button.grid(row=0, column=4, columnspan=1, sticky=tk.NSEW)
        history_button = tk.Button(master=self.command_button_frame,  text="History", foreground="black", background="white", command=self.history_callback)
        history_button.grid(row=0, column=5, columnspan=1, sticky=tk.NSEW)
        cdp_neighbors_button = tk.Button(master=self.command_button_frame,  text="CDP Neighbors", foreground="black", background="white", command=self.cdp_neighbors_callback)
        cdp_neighbors_button.grid(row=1, column=0, columnspan=1, sticky=tk.NSEW)
        etherchannel_button = tk.Button(master=self.command_button_frame,  text="Etherchannel Detail", foreground="black", background="white", command=self.etherchannel_detail_callback)
        etherchannel_button.grid(row=1, column=1, columnspan=1, sticky=tk.NSEW)
        macaddr_button = tk.Button(master=self.command_button_frame, text="Mac Address-Table", foreground="black", background="white", command=self.mac_address_callback)
        macaddr_button.grid(row=1, column=2, columnspan=1, sticky=tk.NSEW)
        tranceiver_button = tk.Button(master=self.command_button_frame,  text="Transceiver Detail", foreground="black", background="white", command=self.transceiver_detail_callback)
        tranceiver_button.grid(row=1, column=3, columnspan=1, sticky=tk.NSEW)
        ssh_button = tk.Button(master=self.command_button_frame,  text="Show SSH", foreground="black", background="white", command=self.show_ssh_connections_callback)
        ssh_button.grid(row=1, column=4, columnspan=1, sticky=tk.NSEW)
        console_button = tk.Button(master=self.command_button_frame,  text="Console", foreground="black", background="white", command=self.console_callback)
        console_button.grid(row=1, column=5, columnspan=1, sticky=tk.NSEW)

        # Populate interface configuration frame.
        desc_validate = self.interface_frame.register(self.description_box_validate)
        vlan_validate = self.interface_frame.register(self.vlan_box_validate)
        int_select_label = tk.Label(master=self.interface_frame, text="Select Interface:")
        int_select_label.grid(row=0, rowspan=1, column=0, columnspan=1, sticky=tk.NSEW)
        self.interface_drop_down = ttk.Combobox(master=self.interface_frame, textvariable=self.interface_selection, values=self.interfaces_list)
        self.interface_drop_down.bind('<<ComboboxSelected>>', self.select_interface)        # Set callback binding for combobox cause it's odd.
        self.interface_drop_down.grid(row=0, rowspan=1, column=1, columnspan=7, sticky=tk.NSEW)
        port_channel_button = tk.Button(master=self.interface_frame, text="Create Port Channel", foreground="black", background="white", command=self.port_channel_callback)
        port_channel_button.grid(row=0, column=8, columnspan=2, sticky=tk.EW)
        int_range_select_label = tk.Label(master=self.interface_frame, text="Range:")
        int_range_select_label.grid(row=1, rowspan=1, column=0, columnspan=1, sticky=tk.EW)
        self.interface_range_drop_down = ttk.Combobox(master=self.interface_frame, textvariable=self.interface_range_selection, values=self.interfaces_list)
        self.interface_range_drop_down.bind('<<ComboboxSelected>>', self.select_range_interface) 
        self.interface_range_drop_down.grid(row=1, rowspan=1, column=1, columnspan=7, sticky=tk.EW)
        description_label = tk.Label(master=self.interface_frame, text="Description: ")
        description_label.grid(row=2, rowspan=1, column=0, columnspan=2, sticky=tk.W)
        self.interface_description_box = tk.Entry(master=self.interface_frame, width=10, validate="key", validatecommand=(desc_validate, '%P'))
        self.interface_description_box.grid(row=2, column=2, columnspan=8, sticky=tk.EW)
        int_shutdown_checkbox = tk.Checkbutton(master=self.interface_frame, text='shutdown', variable=self.int_shutdown_check, onvalue=True, offvalue=False, command=self.shutdown_callback)
        int_shutdown_checkbox.grid(row=3, rowspan=1, column=0, columnspan=10, sticky=tk.W)
        sw_mo_acc_checkbox = tk.Checkbutton(master=self.interface_frame, text='switchport mode access', variable=self.sw_mo_acc_check, onvalue=True, offvalue=False, command=self.sw_mo_acc_callback)
        sw_mo_acc_checkbox.grid(row=4, rowspan=1, column=0, columnspan=10, sticky=tk.W)
        sw_mo_acc_vlan_label = tk.Label(master=self.interface_frame, text="switchport access vlan ")
        sw_mo_acc_vlan_label.grid(row=5, rowspan=1, column=0, columnspan=2, sticky=tk.W)
        self.access_vlan_box = tk.Entry(master=self.interface_frame, width=10, validate="key", validatecommand=(vlan_validate, "%P"))
        self.access_vlan_box.grid(row=5, column=2, columnspan=8, sticky=tk.EW)
        sw_voice_vlan_label = tk.Label(master=self.interface_frame, text="switchport voice vlan ")
        sw_voice_vlan_label.grid(row=6, rowspan=1, column=0, columnspan=2, sticky=tk.W)
        self.voice_vlan_box = tk.Entry(master=self.interface_frame, width=10, validate="key", validatecommand=(vlan_validate, "%P"))
        self.voice_vlan_box.grid(row=6, column=2, columnspan=8, sticky=tk.EW)
        self.spantree_portfast = tk.Checkbutton(master=self.interface_frame, text='spanning-tree portfast', variable=self.spantree_portfast_check, onvalue=True, offvalue=False, command=self.spantree_callback)
        self.spantree_portfast.grid(row=7, rowspan=1, column=0, columnspan=5, sticky=tk.W)
        self.spantree_bpduguard = tk.Checkbutton(master=self.interface_frame, text='spanning-tree bpduguard', variable=self.spantree_bpduguard_check, onvalue=True, offvalue=False, command=self.spantree_callback)
        self.spantree_bpduguard.grid(row=7, rowspan=1, column=5, columnspan=5, sticky=tk.W)
        sw_mo_trunk_checkbox = tk.Checkbutton(master=self.interface_frame, text='switchport mode trunk', variable=self.sw_mo_trunk_check, onvalue=True, offvalue=False, command=self.sw_mo_trunk_callback)
        sw_mo_trunk_checkbox.grid(row=8, rowspan=1, column=0, columnspan=10, sticky=tk.W)
        sw_mo_trunk_vlan_label = tk.Label(master=self.interface_frame, text="switchport trunk native vlan ")
        sw_mo_trunk_vlan_label.grid(row=9, rowspan=1, column=0, columnspan=2, sticky=tk.W)
        self.trunk_vlan_box = tk.Entry(master=self.interface_frame, width=10, validate="key", validatecommand=(vlan_validate, "%P"))
        self.trunk_vlan_box.grid(row=9, column=2, columnspan=8, sticky=tk.EW)
        set_interface_button = tk.Button(master=self.interface_frame, text="Set Interface", foreground="black", background="white", command=self.interface_submit_callback)
        set_interface_button.grid(row=10, column=0, columnspan=10, sticky=tk.NSEW)

        # Populate vlan configuration frame.
        vlan_desc_validate = self.vlan_frame.register(self.vlan_description_box_validate)
        ip_validate = self.vlan_frame.register(self.vlan_ip_address_validate)
        vlan_select_label = tk.Label(master=self.vlan_frame, text="Select VLAN:")
        vlan_select_label.grid(row=0, rowspan=1, column=0, columnspan=2, sticky=tk.EW)
        self.vlan_drop_down = ttk.Combobox(master=self.vlan_frame, textvariable=self.vlan_selection, values=self.vlans_list)
        self.vlan_drop_down.bind('<<ComboboxSelected>>', self.select_vlan)        # Set callback binding for combobox cause it's odd.
        self.vlan_drop_down.grid(row=0, rowspan=1, column=2, columnspan=8, sticky=tk.EW)
        vlan_description_label = tk.Label(master=self.vlan_frame, text="Description: ")
        vlan_description_label.grid(row=1, rowspan=1, column=0, columnspan=2, sticky=tk.W)
        self.vlan_description_box = tk.Entry(master=self.vlan_frame, width=10, validate="key", validatecommand=(vlan_desc_validate, '%P'))
        self.vlan_description_box.grid(row=1, column=2, columnspan=8, sticky=tk.EW)
        ipaddr_label = tk.Label(master=self.vlan_frame, text="ip address ")
        ipaddr_label.grid(row=3, rowspan=1, column=0, columnspan=2, sticky=tk.W)
        self.vlan_ipaddr_box = tk.Entry(master=self.vlan_frame, width=10, validate="key", validatecommand=(ip_validate, "%P"))
        self.vlan_ipaddr_box.grid(row=3, column=2, columnspan=8, sticky=tk.EW)
        vlan_shutdown_button = tk.Checkbutton(master=self.vlan_frame, text='shutdown', variable=self.vlan_shutdown_check, onvalue=True, offvalue=False, command=self.vlan_shutdown_callback)
        vlan_shutdown_button.grid(row=4, rowspan=1, column=0, columnspan=10, sticky=tk.W)
        set_vlan_button = tk.Button(master=self.vlan_frame, text="Set VLAN", foreground="black", background="white", command=self.vlan_submit_callback)
        set_vlan_button.grid(row=10, column=0, columnspan=10, sticky=tk.NSEW)

        # Populate upload config frame.
        self.text_box = tk.Text(master=self.upload_frame, width=10, height=5)
        self.text_box.grid(row=0, rowspan=9, column=0, columnspan=10, sticky=tk.NSEW)
        scroll=tk.Scrollbar(master=self.upload_frame, orient='vertical', command=self.text_box.yview)    # Add a scrollbar.
        scroll.grid(row=0, rowspan=9, column=10, sticky=tk.NS)
        self.text_box['yscrollcommand'] = scroll.set         # Link scroll value back to text box.
        upload_button = tk.Button(master=self.upload_frame,  text="Upload Config", foreground="black", background="white", command=self.upload_config_callback)
        upload_button.grid(row=9, column=0, columnspan=10, sticky=tk.NSEW)

        # Set window initialized flag.
        self.window_is_initialized = True

    ###########################################################################
    #
    #                           DROPDOWN
    #                             FRAME
    #
    ###########################################################################
    def drop_down_callback(self, event) -> None:
        """
        This method is called everytime a new item is selected in the dropdown menu.

        Parameters:
        -----------
            event - The virtual event given to us by the binding of this method to the drop_down object.

        Returns:
        --------
            Nothing
        """
        # Get the index of the currently selected device.
        device_index = self.drop_down.current()
        # Get device connection.
        connection = self.ssh_connections[device_index]

        # Print log.
        self.logger.info(f"Selected device: {self.ip_list[device_index]}. Getting data...")

        # Check if a valid choice has been made.
        if device_index != -1 and (self.ssh_connections[device_index] is None or not self.ssh_connections[device_index].is_alive()):
            # Get the current selected device.
            device = self.devices[device_index]
            # Open ssh connection with switch.
            connection = ssh(device)
            # Store the new connection in the ssh connections list.
            self.ssh_connections[device_index] = connection

        #######################################################################
        # Update config window component data with the new device.
        #######################################################################
        # Check if connection is good.
        if connection is not None and connection.is_alive():
            # Enable config window components. Othewise textbox won't update with input.
            self.enable()
            # Get device.
            device = self.devices[device_index]
            # Update interfaces list and drop down menu.
            self.interfaces_list = device["interfaces"]
            self.interface_drop_down["values"] = [interface["name"] + " " + interface["description"] for interface in self.interfaces_list]
            self.interface_range_drop_down["values"] = [interface["name"] + " " + interface["description"] for interface in self.interfaces_list]
            self.interface_selection.set("No interface is selected")
            self.interface_range_selection.set("No interface is selected")
            # Update vlans list and drop down menu.
            self.vlans_list = device["vlans"]
            self.vlan_drop_down["values"] = [vlan["vlan"] + " " + vlan["name"] for vlan in self.vlans_list]
            self.vlan_selection.set("No vlan is selected")
            # Update config component.
            config_data = device["config"]
            self.text_box.delete("1.0", tk.END)
            self.text_box.insert(tk.END, config_data)

            # Disable interface and vlan frame items.
            for child in self.interface_frame.winfo_children():
                # Only disable if the child isn't the dropdown.
                if child.widgetName != "ttk::combobox":
                    # Disable element.
                    child.configure(state="disable")
            for child in self.vlan_frame.winfo_children():
                # Only disable if the child isn't the dropdown.
                if child.widgetName != "ttk::combobox":
                    # Disable element.
                    child.configure(state="disable")

    def refresh_config_callback(self) -> None:
        """
        This method is called everytime the REFRESH button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Clear interface and vlan selection.
        self.interface_selection.set("No interface is selected")
        self.interface_range_selection.set("No interface is selected")
        self.vlan_selection.set("No vlan is selected")
        # Refresh info.
        self.refresh_device_info(connection, device)

    def write_config_callback(self) -> None:
        """
        This method is called everytime the WRITE button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info("WRITING running configuration...")
        # Write config.
        try:
            output = connection.save_config()
        except NotImplementedError:
            output = connection.send_command("write")

        # Log if writing was successful.
        output = output.replace("\n", " ")
        self.logger.info(f"'{output}'")

        # Show messagebox.
        messagebox.showinfo(title="Write Config Info", message=output, parent=self.window)

    ###########################################################################
    #
    #                             BUTTON
    #                             FRAME
    #
    ###########################################################################
    def interface_status_callback(self) -> None:
        """
        This method is called everytime the Interface Status button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'interface status' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output = connection.send_command("show interface status")
            # Open a new popup window with the output text.
            text_popup(output, x_grid_size=12)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def show_log_callback(self) -> None:
        """
        This method is called everytime the Show Log button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show log' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output = connection.send_command("show log")
            # Open a new popup window with the output text.
            text_popup(output, x_grid_size=15, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)


    def test_port_link_callback(self) -> None:
        """
        This method is called everytime the Test Port Link Quality button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Open a window asking for the user to select an interface from the dropdown menu.
            self.popup = ListPopup()
            selection = self.popup.open([interface["name"] for interface in self.interfaces_list], prompt="Select port to test:")
            # Check if selection is valid.
            if selection is not None:
                # Run command.
                output = connection.send_command(f"test cable tdr interface {selection}")
                # Sleep to give time for the command to run.
                time.sleep(0.1)
                # Get test results.
                output = connection.send_command(f"show cable tdr interface {selection}")
                
                # Print log.
                self.logger.info(f"Sending button command 'test cable tdr interface {selection}' to {device['host']}")

                # Open a new popup window with the output text.
                text_popup(output, x_grid_size=10, y_grid_size=3)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)


    def show_interface_errors_callback(self) -> None:
        """
        This method is called everytime the Show Interface Errors button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show interface counter error' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output = connection.send_command("show interface counter error")
            # Open a new popup window with the output text.
            text_popup(output, x_grid_size=11, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)


    def clear_interface_errors_callback(self) -> None:
        """
        This method is called everytime the Clear Interface Errors button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'clear counters' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output = connection.send_command("clear counters", expect_string="\[confirm\]")
            connection.send_command("\n", expect_string="#")
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def history_callback(self) -> None:
        """
        This method is called evertime the History button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show history' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output = connection.send_command("show history")
            # Open a new popup window with the output text.
            text_popup(output, x_grid_size=11, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def cdp_neighbors_callback(self) -> None:
        """
        This method is called everytime the CDP Neighbors button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show cdp neighbors' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output1 = connection.send_command("show cdp neighbors")
            output2 = connection.send_command("show cdp neighbors detail")
            # Open a new popup window with the output text.
            text_popup(output1 + "\n\n\n\n" + output2, x_grid_size=11, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def etherchannel_detail_callback(self) -> None:
        """
        This method is called everytime the Etherchannel Detail button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show etherchannel detail' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output = connection.send_command("show etherchannel detail")
            # Open a new popup window with the output text.
            text_popup(output, x_grid_size=11, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def mac_address_callback(self) -> None:
        """
        This method is called everytime the Mac Address-Table button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Open a window asking for the user to select an interface from the dropdown menu.
            self.popup = ListPopup()
            selection = self.popup.open([interface["name"] for interface in self.interfaces_list], prompt="Select an interface to display mac address table for:")
            # Check if selection is valid.
            if selection is not None:
                # Run command.
                output = connection.send_command(f"show mac address-table | include {selection}")
                
                # Print log.
                self.logger.info(f"Sending button command 'show mac address-table | {selection}' to {device['host']}")

                # Open a new popup window with the output text.
                text_popup(output, x_grid_size=10, y_grid_size=3)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def transceiver_detail_callback(self) -> None:
        """
        This method is called everytime the Transceiver Detail button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show interfaces transceiver detail' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Open a window asking for the user to select an interface from the dropdown menu.
            self.popup = ListPopup()
            selection = self.popup.open([interface["name"] for interface in self.interfaces_list], prompt="Select an interface to display transceiver data for:")
            # Check if selection is valid.
            if selection is not None:
                # Run command
                output = connection.send_command(f"show interface {selection} transceiver detail")
                # Open a new popup window with the output text.
                text_popup(output, x_grid_size=11, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def show_ssh_connections_callback(self) -> None:
        """
        This method is called everytime the Show SSH button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Print log.
        self.logger.info(f"Sending button command 'show ip ssh' to {device['host']}")

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Run command
            output1 = connection.send_command("show ip ssh")
            output2 = connection.send_command("show ssh")
            # Open a new popup window with the output text.
            text_popup(output1 + "\n\n\n" + output2, x_grid_size=11, y_grid_size=10)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def port_channel_callback(self) -> None:
        """
        This method is called everytime the Create Port Channel button is pressed.
        
        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Create instance variables.
        selections = None
        channel_number = None

        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Send command to switch and open a message box with the command output.
        if connection is not None and connection.is_alive():
            # Open a window asking for the user to select interfaces from the dropdown menu.
            self.popup = MultipleListPopup()
            selections = self.popup.open([interface["name"] for interface in self.interfaces_list], prompt="Choose your interfaces: ")
            # Check if selections completed successfully, if so then continue to ask for channel number.\
            if selections is not None:
                # Open a popup window and ask user what number port channel interface they want to connection to.
                self.popup = ListPopup()
                channel_number = self.popup.open(list(range(1,10)), prompt="Choose the port channel number:")

            # Check if we got all info from the user before running commands.
            command_list = ['config t']
            if channel_number is not None:
                # Loop through each interface and build a command config list.
                for interface in selections:
                    command_list.append(f"interface {interface}")
                    command_list.append(f"channel-group {channel_number} mode active")
                # Exit config mode.
                command_list.append("end")

                # Print log.
                self.logger.info(f"Sending button commands to make Po{channel_number} on interfaces {selections} to {device['host']}")
                # Send config set will sometimes bug/timeout. Not my problem.
                try:
                    # Get privs.
                    connection.enable()
                    # Execute switch config.
                    output = connection.send_config_set(command_list, exit_config_mode=False)
                    # Print log.
                    self.logger.info(f"Successfully created port channel Po{channel_number} on {device['host']}")
                except Exception as error:
                    # Print log.
                    self.logger.error("Something goofy happened while sending port channel commands: ", exc_info=error, stack_info=True)
                    # More debug.
                    self.logger.info(f"Attempted command list: {command_list}")

                # Update interface, vlans, and config after adding port channel.
                self.refresh_device_info(connection, device)

                # Open text window with the output.
                text_popup(output)
        else:
            # Display message box saying the command was unable to complete.
            messagebox.showwarning(title="Info", message="The command was unable to complete because the connection to the device is currently not alive or was never opened.", parent=self.window)

    def console_callback(self) -> None:
        """
        This method is called everytime the Console button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get current device ip.
        addr = device["ip_address"]


        # Open new CMD window with an ssh connection to the switch.
        subprocess.Popen(f"start /wait ssh {device['username']}@{addr}", shell=True)


    ###########################################################################
    #
    #                           INTERFACE
    #                             FRAME
    #
    ###########################################################################
    def select_interface(self, event) -> None:
        """
        This method is called everytime a new item is selected from the interface dropdown menu.

        Parameters:
        -----------
            event - Given to us by the ComboBox function, kinda useless right now.

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_interface_index = self.interface_drop_down.current()
        # Reset range dropdown.
        self.interface_range_drop_down.set("No interface is selected")
        # Get current interface.
        interface = self.interfaces_list[current_interface_index]

        # Enable checkboxes and entry boxes.
        for child in self.interface_frame.winfo_children():
            # Enable element.
            child.configure(state="normal")

        # Update interface description box.
        self.interface_description_box.delete(0, tk.END)
        self.interface_description_box.insert(0, interface["description"])

        # Update shutdown checkbox.
        self.int_shutdown_check.set(interface["shutdown"])

        # Update switch mode access checkbox.
        self.sw_mo_acc_check.set(interface["switchport mode access"])
        # If sw mo acc checkbox is enabled. then enable the entry box for the vlan.
        if self.sw_mo_acc_check.get():
            # Enable the entry box.
            self.access_vlan_box.configure(state="normal")
            self.voice_vlan_box.configure(state="normal")
            self.spantree_portfast.configure(state="normal")
            self.spantree_bpduguard.configure(state="normal")
            # Get data.
            self.access_vlan_box.delete(0, tk.END)
            self.access_vlan_box.insert(0, interface["switchport access vlan"])
            self.voice_vlan_box.delete(0, tk.END)
            self.voice_vlan_box.insert(0, interface["switchport voice vlan"])
            self.spantree_portfast_check.set(interface["spanning-tree portfast"])
            self.spantree_bpduguard_check.set(interface["spanning-tree bpduguard enable"])
        else:
            # Disable entry box.
            self.access_vlan_box.configure(state="disable")
            self.voice_vlan_box.configure(state="disable")
            self.spantree_portfast.configure(state="disable")
            self.spantree_bpduguard.configure(state="disable")

        self.sw_mo_trunk_check.set(interface["switchport mode trunk"])
        # If sw mo acc checkbox is enabled. then enable the entry box for the vlan.
        if self.sw_mo_trunk_check.get():
            # Enable the entry box.
            self.trunk_vlan_box.configure(state="normal")
            # Get data.
            self.trunk_vlan_box.delete(0, tk.END)
            self.trunk_vlan_box.insert(0, interface["switchport trunk native vlan"])
        else:
            # Disable entry box.
            self.trunk_vlan_box.configure(state="disable")

    def select_range_interface(self, event) -> None:
        """
        This method is called everytime a new item is selected from the range interface dropdown menu.

        Parameters:
        -----------
            event - Given to us by the ComboBox function, kinda useless right now.

        Returns:
        --------
            Nothing
        """
        # Clear all input boxes and checkmarks.
        self.interface_description_box.delete(0, tk.END)
        self.interface_description_box.insert(0, "-")
        self.int_shutdown_check.set(False)
        self.sw_mo_acc_check.set(False)
        self.sw_mo_trunk_check.set(False)
        self.spantree_portfast_check.set(False)
        self.spantree_bpduguard_check.set(False)
        self.access_vlan_box.delete(0, tk.END)
        self.voice_vlan_box.delete(0, tk.END)
        self.trunk_vlan_box.delete(0, tk.END)
        self.access_vlan_box.insert(0, "0")
        self.voice_vlan_box.insert(0, "0")
        self.trunk_vlan_box.insert(0, "0")

        # Disable vlan entry boxes and spanning-tree checkboxes.
        self.access_vlan_box.configure(state="disable")
        self.voice_vlan_box.configure(state="disable")
        self.trunk_vlan_box.configure(state="disable")

    def shutdown_callback(self) -> None:
        """
        This method is called everytime the shutdown checkbox is ticked.
        """
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]
            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["config_has_changed"] = True
        else:
            # Get current interface.
            interface = self.interfaces_list[self.interface_drop_down.current()]
            # Update interface dictionary.
            interface["config_has_changed"] = True

        # Check if interface range is selected. Update here instead of update_window method to avoid user confusion.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]

            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["shutdown"] = self.int_shutdown_check.get()

    def sw_mo_acc_callback(self) -> None:
        """
        This method is called everytime the switch mode access checkbox is ticked.
        """
        # Enable access elements.
        self.access_vlan_box.configure(state="normal")
        self.voice_vlan_box.configure(state="normal")
        self.spantree_portfast.configure(state="normal")
        self.spantree_bpduguard.configure(state="normal")
        # Disable trunk elements.
        self.sw_mo_trunk_check.set(False)
        self.trunk_vlan_box.configure(state="disable")
        # Set flag indicating that the inteface has changed, and needs to be updated.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]
            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["config_has_changed"] = True
        else:
            # Get current interface.
            interface = self.interfaces_list[self.interface_drop_down.current()]
            # Update interface dictionary.
            interface["config_has_changed"] = True

        # Check if interface range is selected. Update here instead of update_window method to avoid user confusion.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]

            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["switchport mode access"] = self.sw_mo_acc_check.get()
                interface["switchport mode trunk"] = False

    def spantree_callback(self) -> None:
        """
        This method is called everytime either of the spanning-tree checkboxes are ticked.
        """
        # Get current interface.
        interface = self.interfaces_list[self.interface_drop_down.current()]
        # Update interface dictionary.
        interface["config_has_changed"] = True

        # Check if interface range is selected. Update here instead of update_window method to avoid user confusion.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]

            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["spanning-tree portfast"] = self.spantree_portfast_check.get()
                interface["spanning-tree bpduguard enable"] = self.spantree_bpduguard_check.get()

    def sw_mo_trunk_callback(self) -> None:
        """
        This method is called everytime the switch mode trunk checkbox is ticked.
        """
        # Enable access elements.
        self.trunk_vlan_box.configure(state="normal")
        # Disable access elements.
        self.sw_mo_acc_check.set(False)
        self.access_vlan_box.configure(state="disable")
        self.voice_vlan_box.configure(state="disable")
        self.spantree_portfast.configure(state="disable")
        self.spantree_bpduguard.configure(state="disable")
        # Set flag indicating that the inteface has changed, and needs to be updated.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]
            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["config_has_changed"] = True
        else:
            # Get current interface.
            interface = self.interfaces_list[self.interface_drop_down.current()]
            # Update interface dictionary.
            interface["config_has_changed"] = True

        # Check if interface range is selected. Update here instead of update_window method to avoid user confusion.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]

            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["switchport mode trunk"] = self.sw_mo_trunk_check.get()
                interface["switchport mode access"] = False

    def description_box_validate(self, entry_contents) -> bool:
        """
        This method is called everytime the contents of the description box are changed. It verifies input validity.

        Parameters:
        -----------
            entry_contents - the text from the entry box.

        Returns:
        --------
            bool - True if input is valid.
        """
        # Create instance variables.
        is_valid = True

        # Check input validity.
        if re.compile('[@_!#$%^&*()<>?/\\\|}{~:[\]]').search(entry_contents) != None:
            # Set toggle.
            is_valid = False
        else:
            # Set flag indicating that the inteface has changed, and needs to be updated.
            if self.interface_range_drop_down.current() != -1:
                # Get interfaces within range.
                interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]
                # Loop through interfaces and update them.
                for interface in interfaces:
                    # Update interface dictionary.
                    interface["config_has_changed"] = True
            else:
                # Get current interface.
                interface = self.interfaces_list[self.interface_drop_down.current()]
                # Update interface dictionary.
                interface["config_has_changed"] = True

        # Check if interface range is selected. Update here instead of update_window method to avoid user confusion.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]

            # Loop through interfaces and update them.
            for interface in interfaces:
                # Update interface dictionary.
                interface["description"] = entry_contents

        # Just return true for now. So far, I can't think of any restrictions that the switch description needs.
        return is_valid

    def vlan_box_validate(self, entry_contents) -> None:
        """
        This method is called everytime the contents of the vlan number boxes are changed. It verifies input validity.

        Parameters:
        -----------
            entry_contents - the text from the entry box.

        Returns:
        --------
            bool - True if input is valid.
        """
        # Only allow digits to be input.
        is_valid = False
        if str.isdigit(entry_contents) or entry_contents == "":
            # Set toggle.
            is_valid = True

            # Set flag indicating that the inteface has changed, and needs to be updated.
            if self.interface_range_drop_down.current() != -1:
                # Get interfaces within range.
                interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]
                # Loop through interfaces and update them.
                for interface in interfaces:
                    # Update interface dictionary.
                    interface["config_has_changed"] = True
            else:
                # Get current interface.
                interface = self.interfaces_list[self.interface_drop_down.current()]
                # Update interface dictionary.
                interface["config_has_changed"] = True

        # Check if interface range is selected. Update here instead of update_window method to avoid user confusion.
        if self.interface_range_drop_down.current() != -1:
            # Get interfaces within range.
            interfaces = self.interfaces_list[self.interface_drop_down.current() : self.interface_range_drop_down.current() + 1]

            # Loop through interfaces and update them.
            for interface in interfaces:
                # Get the currently selected widget.
                current_focus_widget = self.interface_frame.focus_get()
                # Check if vlan box has been altered.
                if current_focus_widget == self.access_vlan_box:
                    # Update interface dictionary.
                    interface["switchport access vlan"] = entry_contents
                elif current_focus_widget == self.voice_vlan_box:
                    # Update interface dictionary.
                    interface["switchport voice vlan"] = entry_contents
                elif current_focus_widget == self.trunk_vlan_box:
                    # Update interface dictionary.
                    interface["switchport trunk native vlan"] = entry_contents

        return is_valid

    def interface_submit_callback(self) -> None:
        """
        This method is called everytime the interface submit button is pressed.
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # Create command list.
        command_list = ["conf t"]
        for interface in self.interfaces_list:
            # Check if interface actually needs updating.
            if interface["config_has_changed"]:
                # Check if we are enable or disabling the box.
                if interface["switchport mode access"]:
                    # Navigate into enterface.
                    command_list.append(f"interface {interface['name']}")

                    # Set toggled command.
                    command_list.append("switchport mode access")
                    command_list.append(f"no switchport trunk native vlan")

                    # Set mode access vlan.
                    if str(interface["switchport access vlan"]) != "0" and len(interface["switchport access vlan"]) > 0:
                        command_list.append(f"switchport access vlan {interface['switchport access vlan']}")
                    else:
                        command_list.append("no switchport access vlan")
                    # Set voice vlan.
                    if str(interface["switchport voice vlan"]) != "0" and len(interface["switchport voice vlan"]) > 0:
                        command_list.append(f"switchport voice vlan {interface['switchport voice vlan']}")
                    else:
                        command_list.append("no switchport voice vlan")

                    # Set spanning tree portfast.
                    if interface["spanning-tree portfast"]:
                        command_list.append("spanning-tree portfast")
                    else:
                        command_list.append("no spanning-tree portfast")
                    # Set spanning tree bpduguard.
                    if interface["spanning-tree bpduguard enable"]:
                        command_list.append("spanning-tree bpduguard enable")
                    else:
                        command_list.append("no spanning-tree bpduguard enable")
                elif interface["switchport mode trunk"]:
                    # Navigate into enterface.
                    command_list.append(f"interface {interface['name']}")

                    # Set toggled command.
                    command_list.append("switchport mode trunk")
                    
                    # Set access vlan and spanning-tree.
                    command_list.append("no switchport access vlan")
                    command_list.append("no spanning-tree portfast")
                    command_list.append("no spanning-tree bpduguard enable")

                    # Set trunk vlan.
                    if str(interface["switchport trunk native vlan"]) != "0" and len(interface["switchport trunk native vlan"]) > 0:
                        command_list.append(f"switchport trunk native vlan {interface['switchport trunk native vlan']}")
                    else:
                        command_list.append("no switchport trunk native vlan")
                else:
                    # If both access and trunk checkboxes are unticked, then defualt the port.
                    command_list.append(f"default interface {interface['name']}")
                    # Navigate into enterface.
                    command_list.append(f"interface {interface['name']}")

                # Set description.
                if interface["description"] != "-":
                    if len(interface["description"]) > 0:
                        command_list.append(f"description {interface['description']}")
                    else:
                        command_list.append("no description")

                # Set port enabled or disabled.
                if interface["shutdown"]:
                    command_list.append("shutdown")
                else:
                    command_list.append("no shutdown")

        # Attach end command.
        command_list.append("end")

        # Print log.
        self.logger.info(f"Sending interface commands {command_list} to {device['host']}")

        # Get privs.
        connection.enable()
        # Run commands.
        connection.send_config_set(command_list, exit_config_mode=False)
        self.refresh_device_info(connection, device)
        # Reset dropdowns if using a ranged config.
        if self.interface_range_selection.get() != "No interface is selected":
            self.interface_selection.set("No interface is selected")
            self.interface_range_selection.set("No interface is selected")

    ###########################################################################
    #
    #                             VLAN
    #                             FRAME
    #
    ###########################################################################
    def select_vlan(self, event) -> None:
        """
        This method is called everytime a new item is selected from the vlan dropdown menu.

        Parameters:
        -----------
            event - Given to us by the ComboBox function, kinda useless right now.

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_interface_index = self.vlan_drop_down.current()
        # Get current interface.
        vlan_interface = self.vlans_list[current_interface_index]

        # Enable checkboxes and entry boxes.
        for child in self.vlan_frame.winfo_children():
            # Enable element.
            child.configure(state="normal")

        # Vlans are tricky.
        try:
            # Update vlan description box.
            self.vlan_description_box.delete(0, tk.END)
            self.vlan_description_box.insert(0, vlan_interface["description"])
            # Update vlan ip addr box.
            self.vlan_ipaddr_box.delete(0, tk.END)
            self.vlan_ipaddr_box.insert(0, vlan_interface["ip address"])
            # Update vlan shutdown checkbox.
            self.vlan_shutdown_check.set(vlan_interface["shutdown"])
        except KeyError:
            self.logger.error(f"Unable to get data for vlan {vlan_interface['name']}. It might not be completely configured, check the switch config.")
            messagebox.showerror(title="Failed", message=f"Unable to get data for vlan {vlan_interface['name']}. It might not be completely configured, check the switch config.", parent=self.window)

    def vlan_shutdown_callback(self) -> None:
        """
        This method is called everytime the vlan shutdown checkbox is ticked.
        """
        # Get current interface.
        vlan_interface = self.vlans_list[self.vlan_drop_down.current()]
        # Update interface dictionary.
        vlan_interface["config_has_changed"] = True

    def vlan_description_box_validate(self, entry_contents) -> None:
        """
        This method is called everytime the contents of the description box are changed. It verifies input validity.

        Parameters:
        -----------
            entry_contents - the text from the entry box.

        Returns:
        --------
            bool - True if input is valid.
        """
        # Get current interface.
        vlan_interface = self.vlans_list[self.vlan_drop_down.current()]
        # Update interface dictionary.
        vlan_interface["config_has_changed"] = True

        # Just return true for now. So far, I can't think of any restrictions that the switch description needs.
        return True

    def vlan_ip_address_validate(self, entry_contents) -> None:
        """
        This method is called everytime the contents of the vlan ip addr boxe is changed. It verifies input validity.

        Parameters:
        -----------
            entry_contents - the text from the entry box.

        Returns:
        --------
            bool - True if input is valid.
        """
        # Only allow digits and periods to be input.
        is_valid = False
        if not re.search('[a-zA-Z]', entry_contents) or entry_contents == "":
            # Set toggle.
            is_valid = True

            # Get current interface.
            vlan_interface = self.vlans_list[self.vlan_drop_down.current()]
            # Update interface dictionary.
            vlan_interface["config_has_changed"] = True

        return is_valid

    def vlan_submit_callback(self) -> None:
        """
        This method is called everytime the vlan submit button is pushed.
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device.
        device = self.devices[current_device_index]
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]

        # VLANs really are tricksters.
        try:
            # Create command list.
            command_list = ["conf t"]
            for vlan_interface in self.vlans_list:
                # Check if interface actually needs updating.
                if vlan_interface["config_has_changed"]:
                    # Navigate into vlan.
                    command_list.append(f"vlan {vlan_interface['vlan']}")
                    if len(vlan_interface["description"]) > 0:
                        # Change vlan name.
                        command_list.append(f"name {vlan_interface['description']}")
                    else:
                        # Change vlan name.
                        command_list.append("no name")

                    # Navigate into interface.
                    command_list.append(f"interface Vlan{vlan_interface['vlan']}")

                    # Set description.
                    if len(vlan_interface["description"]) > 0:
                        command_list.append(f"description {vlan_interface['description']}")
                    else:
                        command_list.append("no description")

                    # Set vlan ip.
                    if str(vlan_interface["ip address"]) != "0" and len(vlan_interface["ip address"]) > 0:
                        command_list.append(f"ip address {vlan_interface['ip address']}")
                    else:
                        command_list.append("no ip address")

                    # Set shutdown.
                    if vlan_interface["shutdown"]:
                        command_list.append("shutdown")
                    else:
                        command_list.append("no shutdown")

            # Attach end command.
            command_list.append("end")

            # Print log.
            self.logger.info(f"Sending interface commands {command_list} to {device['host']}")

            # Get privs.
            connection.enable()
            # Run commands.
            connection.send_config_set(command_list, exit_config_mode=False)
            self.refresh_device_info(connection, device)
        except KeyError:
                self.logger.error(f"Unable to send commands {command_list} to {device['host']}. An existing VLAN is configured improperly, please fix it using the config window.")
                messagebox.showerror(title="Failed", message=f"Unable to send commands {command_list} to {device['host']}. An existing VLAN is configured improperly, please fix it using the config window.", parent=self.window)

    
    ###########################################################################
    #
    #                          UPLOAD CONFIG
    #                             FRAME
    #
    ###########################################################################
    def upload_config_callback(self) -> None:
        """
        This method is called everytime the Upload Config button is pressed.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Get the current index of the device selected from the dropdown menu.
        current_device_index = self.drop_down.current()
        # Get device and device connection.
        device = self.devices[current_device_index]
        connection = self.ssh_connections[current_device_index]
        # Get config from textbox.
        config = self.text_box.get('1.0', tk.END)

        # Start method in new thread.
        self.upload_text_switch_commands(current_device_index, config)

        # Refresh device info.
        self.refresh_device_info(connection, device)

    def upload_text_switch_commands(self, current_device_index, config) -> None:
        """
        This method gets the data from the config window's textbox and runs the commands in the currently selected switch.

        Parameters:
        -----------
            current_device_index - The current index of the device in the drop down.
            config_commands - The list of commands to execute.

        Returns:
        --------
            Nothing
        """
        # Get connection of device.
        connection = self.ssh_connections[current_device_index]
        # Get device.
        device = self.devices[current_device_index]

        # Print log.
        self.logger.info(f"Uploading config to {device['host']}. Please wait...")

        # Make sure connection is still alive.
        if connection.is_alive():
            # The send_config_set method is very jank and breaks often between netmiko updates.
            try:
                # Split the config up by !.
                config = re.split("!+", config)
                # Cutoff the last configured by text.
                config = config[3:]
                # Compare the new and old config and only run whats changed.
                diff = []
                for section in config:
                    # If the current line in the textbox config doesn't exist in the running config, then append to new list.
                    if not section in device["config"]:
                        # Append to list.
                        diff.append(section)

                # Turn the list back into a string
                commands = ""
                for command in diff:
                    commands += command
                # Split the difference list up by newlines.
                commands = re.split("\n+", commands)
                # Add config command to command list and end to end of command list. Must do this stuff manually for now because netmiko is brokey.
                commands.insert(0, "config t")

                # Get privs.
                connection.enable()
                # Display info message, so the user doesn't think the program crashed.
                messagebox.showinfo(title="Info", message="Please wait while your config is being uploaded.", parent=self.window)
                # Execute switch config.
                output = connection.send_config_set(commands, exit_config_mode=False)
                # Open new popup window containing the commands output.
                text_popup(output)
            except Exception as error:
                self.logger.critical("A NetMiko issue occured while trying to run the config commands.", stack_info=True, exc_info=error)


    def refresh_device_info(self, connection, device) -> None:
        """
        This method uses the given ssh connection to get device interface, vlan, anc config info and 
        stores it in the given device dictionary.

        Parameters:
        -----------
            connection - The ssh connection.
            device - The array to store the data in.

        Returns:
        --------
            Nothing
        """
        # Update device dictionary after uploading config.
        interfaces, vlans, config = get_config_info(connection)
        # Store info in device dictionary.
        device["interfaces"] = interfaces
        device["vlans"] = vlans
        device["config"] = config

        # Update interfaces and vlan lists and dropdowns.
        self.interfaces_list = device["interfaces"]
        self.interface_drop_down["values"] = [interface["name"] + " " + interface["description"] for interface in self.interfaces_list]
        self.interface_range_drop_down["values"] = [interface["name"] + " " + interface["description"] for interface in self.interfaces_list]
        self.vlans_list = device["vlans"]
        self.vlan_drop_down["values"] = [vlan["vlan"] + " " + vlan["name"] for vlan in self.vlans_list]
        # Update config textbox component.
        self.text_box.delete("1.0", tk.END)
        self.text_box.insert(tk.END, config)
        
    def update_window(self) -> None:
        """
        Update the windows UI components and values.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Wait until we get ip info, then initialize window.
        if not self.window_is_initialized and len(self.ip_list) > 0:# and not all(ip is None for ip in self.ip_list) and not all(ip[0] is False for ip in self.ip_list):
            # If the list does not contain tuples that store if the ping was successful then move on.
            if isinstance(self.ip_list[0], Tuple):
                # Remove all ips that are unreachable.
                ips = []
                for addr in self.ip_list:
                    if addr is not None and addr[0] is True:
                        ips.append(f"{addr[1]} {addr[2]}")

                # Remove duplicate entries.
                ips = list(dict.fromkeys(ips))

                # Print log info.
                if len(self.ip_list) - len(ips) > 0:
                    self.logger.info(f"Throwing out {len(self.ip_list) - len(ips)} of {len(self.ip_list)} IPs because they are duplicates or unreachable.")
                # Assign new ip list withing None and False ips.
                self.ip_list = ips

            if len(self.ip_list) <= 0:
                # Print a log warning since we don't have any good ips.
                self.logger.warning("Switch config window did not open because no valid or reachable IPs were given.")
                # Close window.
                self.close_window()
            else:
                if not self.retrieving_devices:
                    # Loop through and grab just the IPs of the devices.
                    addresses = []
                    for addr in self.ip_list:
                        # Split the string containing ip and hostname.
                        temp = addr.split(" ")[0]
                        # Add only ip to the list.
                        addresses.append(temp)
                    
                    # Now that we have a good list of IPs, get device info about each one.
                    Thread(target=ssh_autodetect_switchlist_info, args=(self.usernames, self.passwords, addresses, self.devices)).start()

                    # Set toggle.
                    self.retrieving_devices = True

                # Wait until devices list has been updated.
                if len(self.devices) == len(self.ip_list):
                    # Update hostnames.
                    for i, addr in enumerate(self.ip_list):
                        # Split ip string.
                        addr = addr.split(" ")
                        # Copy devices hostname to ip list.
                        device = self.devices[i]
                        if device is not None and len(device) > 0:
                            hostname = device["host"]
                            device = f"{addr[0]} {hostname}"
                            self.ip_list[i] = device

                    # Set length of ssh_connection list to the same as devices.
                    self.ssh_connections = [None] * len(self.devices)

                    # Initialize window components.
                    self.initialize_window()

                if len(self.devices) >= 1 and self.devices[0] is None:
                    # Close window.
                    self.close_window()
                    # Show error message if device auth failed.
                    messagebox.showwarning(message="Can't authenticate with the given credentials. Please enter the correct username and password.")

        # Only update window components if window is initialized.
        if self.window_is_initialized:
            # Check if the user has selected a valid option from the dropdown, if they have enable config window frames.
            if self.drop_down.current() == -1 or self.ssh_connections[self.drop_down.current()] is None or not self.ssh_connections[self.drop_down.current()].is_alive():
                # Only run is window isn't already disabled.
                if self.is_enabled:
                    # Disable window.
                    self.disable()
                    # Set toggle.
                    self.is_enabled = False
            elif not self.is_enabled:
                # Enable window.
                self.enable()
                # Set toggle.
                self.is_enabled = True

            # Check if the user has selected a valid option from the interfaces dropdown menu.
            if self.interface_drop_down.current() == -1:
                # Disable interface frame items.
                for child in self.interface_frame.winfo_children():
                    # Only disable if the child isn't the dropdown.
                    if child.widgetName != "ttk::combobox" and child.cget("text") != "Create Port Channel":
                        # Disable element.
                        child.configure(state="disable")

            # Check if the user has selected a valid option from the vlan dropdown menu.
            if self.vlan_drop_down.current() == -1:
                # Disable vlan frame items.
                for child in self.vlan_frame.winfo_children():
                    # Only disable if the child isn't the dropdown.
                    if child.widgetName != "ttk::combobox":
                        # Disable element.
                        child.configure(state="disable")

            # If window is enabled and an interface has been selected and not interface range, then update interface data with UI element values.
            if self.is_enabled and self.interface_drop_down.current() != -1 and self.interface_range_drop_down.current() == -1:
                # Get current interface.
                interface = self.interfaces_list[self.interface_drop_down.current()]

                # Update interface dictionary.
                interface["description"] = self.interface_description_box.get()
                interface["shutdown"] = self.int_shutdown_check.get()
                interface["switchport mode access"] = self.sw_mo_acc_check.get()
                interface["switchport mode trunk"] = self.sw_mo_trunk_check.get()
                interface["spanning-tree portfast"] = self.spantree_portfast_check.get()
                interface["spanning-tree bpduguard enable"] = self.spantree_bpduguard_check.get()
                interface["switchport access vlan"] = self.access_vlan_box.get()
                interface["switchport voice vlan"] = self.voice_vlan_box.get()
                interface["switchport trunk native vlan"] = self.trunk_vlan_box.get()

            # If window is enabled and a vlan has been selected, then update interface data with UI element values.
            if self.is_enabled and self.vlan_drop_down.current() != -1:
                # Get current interface.
                vlan_interface = self.vlans_list[self.vlan_drop_down.current()]

                # Update interface dictionary.
                vlan_interface["description"] = self.vlan_description_box.get()
                vlan_interface["ip address"] = self.vlan_ipaddr_box.get()
                vlan_interface["shutdown"] = self.vlan_shutdown_check.get()

            # Call window event loop.
            self.window.update()

    def close_window(self) -> None:
        """
        This method is called when the configure window closes.
        """
        # Set bool value.
        self.window_is_open = False
        self.retrieving_devices = False
        # Clear arrays.
        self.ip_list.clear()
        self.devices.clear()
        # Close any popup windows.
        if self.popup is not None and self.popup.get_is_window_open():
            # Close window.
            self.popup.close_window()
        # Close window.
        if self.window_is_initialized:
            # Print info.
            self.logger.info("Configure window exit action has been invoked. Performing closing actions.")
            # Set toggle.
            self.window_is_initialized = False

            # Attempt to nicely close all ssh connections.
            for connection in self.ssh_connections:
                if connection is not None and connection.is_alive():
                    connection.disconnect()

            # Destroy window.
            self.window.destroy()

    def enable(self) -> None:
        """
        Sets all of the child objects of each frame to be enabled.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Loop through selector frame.
        for child in self.selector_frame.winfo_children():
            # Enable.
            child.configure(state="normal")

        # Loop through command_button frame.
        for child in self.command_button_frame.winfo_children():
            # Enable.
            child.configure(state="normal")

        # Loop through interface frame.
        for child in self.interface_frame.winfo_children():
            if child.widgetName == "ttk::combobox" or child.cget("text") == "Create Port Channel":
                # Enable.
                child.configure(state="normal")
        
        # Loop through vlan frame.
        for child in self.vlan_frame.winfo_children():
            if child.widgetName == "ttk::combobox":
                # Enable.
                child.configure(state="normal")

        # Loop through upload frame.
        for child in self.upload_frame.winfo_children():
            # Can't disable the scrollbar.
            if child.widgetName != "scrollbar":
                # Enable.
                child.configure(state="normal")

    def disable(self) -> None:
        """
        Sets all of the child objects of each frame to be disabled.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Don't set selector frame. We won't to always be able to select a new device.

        # Loop through command_button frame.
        for child in self.command_button_frame.winfo_children():
            # Enable.
            child.configure(state="disable")

        # Loop through interface frame.
        for child in self.interface_frame.winfo_children():
            # Enable.
            child.configure(state="disable")
        
        # Loop through vlan frame.
        for child in self.vlan_frame.winfo_children():
            # Enable.
            child.configure(state="disable")

        # Loop through upload frame.
        for child in self.upload_frame.winfo_children():
            # Can't disable the scrollbar.
            if child.widgetName != "scrollbar":
                # Enable.
                child.configure(state="disable")

    def get_is_window_open(self) -> bool:
        """
        Returns if the window is still open and running.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        return self.window_is_open

    def get_is_window_initialized(self) -> bool:
        """
        Returns if the window has been initialized

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        return self.window_is_initialized
