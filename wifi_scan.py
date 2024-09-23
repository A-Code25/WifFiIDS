#CREATED BY ADITYA MISHRA


import tkinter as tk
from tkinter import simpledialog, messagebox, PhotoImage
from scapy.all import ARP, Ether, srp
import threading
import socket

# Initialize authorized MAC addresses
authorized_macs = {}
scanning = False
gateway_ip = None

def get_gateway_ip():
    global gateway_ip
    gateway_ip = simpledialog.askstring("Gateway IP", "Please enter the Gateway IP address (e.g., 192.168.1.1):")
    if not gateway_ip:
        messagebox.showerror("Input Error", "Gateway IP is required to start the application.")
        root.quit()  # Exit the application if no IP is provided
    else:
        gateway_ip = gateway_ip.strip()  # Ensure no leading/trailing spaces

def add_mac():
    mac = mac_entry.get()
    if mac:
        name = name_entry.get() or "Unknown Device"
        authorized_macs[mac] = name
        update_mac_list()
    else:
        messagebox.showwarning("Input Error", "Please enter a valid MAC address.")

def remove_mac():
    selected = mac_listbox.curselection()
    if selected:
        mac = mac_listbox.get(selected).split(" - ")[0]
        del authorized_macs[mac]
        update_mac_list()
    else:
        messagebox.showwarning("Selection Error", "Please select a MAC address to remove.")

def update_mac_list():
    mac_listbox.delete(0, tk.END)
    for mac, name in authorized_macs.items():
        mac_listbox.insert(tk.END, f"{mac} - {name}")

def scan_network():
    global scanning
    scanning = True
    try:
        # Define the network to scan using the provided gateway IP
        target_ip = f"{gateway_ip}/24"
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]
        detected_macs = {}

        for sent, received in result:
            if not scanning:
                break
            mac = received.hwsrc
            ip = received.psrc
            try:
                device_name = socket.gethostbyaddr(ip)[0] if ip else "Unknown"
            except (socket.herror, socket.gaierror):
                device_name = "Unknown"

            detected_macs[mac] = device_name

            if mac not in authorized_macs:
                messagebox.showwarning("Unauthorized Device", f"Unauthorized MAC: {mac} ({device_name}) detected!")

        # Update listbox with detected devices
        update_mac_list()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during the scan: {str(e)}")
    finally:
        scanning = False

def start_scan():
    if not scanning:
        threading.Thread(target=scan_network).start()

def stop_scan():
    global scanning
    scanning = False

# GUI setup
root = tk.Tk()
root.title("Wi-Fi MAC Address Monitor")
root.geometry("600x400")

# Prompt for gateway IP at startup
get_gateway_ip()



# Entry and buttons for adding/removing MACs
name_entry = tk.Entry(root, width=30)
name_entry.insert(0, "Enter device name")
name_entry.pack(pady=5)

mac_entry = tk.Entry(root, width=30)
mac_entry.insert(0, "Enter MAC address")
mac_entry.pack(pady=5)

add_button = tk.Button(root, text="Add MAC", command=add_mac)
add_button.pack(pady=5)

remove_button = tk.Button(root, text="Remove Selected MAC", command=remove_mac)
remove_button.pack(pady=5)

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan)
stop_button.pack(pady=5)

# Listbox to display authorized MAC addresses
mac_listbox = tk.Listbox(root, width=50, height=15)
mac_listbox.pack(pady=10)

root.mainloop()
