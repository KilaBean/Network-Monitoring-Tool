import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu, simpledialog
import psutil
from scapy.all import sniff, rdpcap, wrpcap, DNS, IP, UDP, DNSQR  # Import DNSQR layer
import threading
from datetime import datetime
from PIL import Image, ImageTk, ImageGrab  # Ensure PIL is installed for image handling
import socket
import time


# Global variables
stop_capture_event = threading.Event()
frame_count = 0  # Global frame count that will not reset
captured_packets = []
session_directories = []
save_file_path = None



# Define the filtering logic for domains
def is_user_accessed(domain_name):
    ignored_domains = [
        "local", "apple.com", "windowsupdate.com", "ubuntu.com", "time.windows.com", 
        "ntp.org", "avast.com", "microsoft.com", "amazon.com", "play.google.com", 
        "www.google-analytics.com", "ogs.google.com", "www.gstatic.com", 
        "ssl.gstatic.com", "accounts.google.com", "www.googleadservice.com"
    ]
    if any(domain_name.endswith(f".{d}") for d in ignored_domains):
        print(f"Ignored domain: {domain_name}")  # Debug output for ignored domains
        return False

    try:
        socket.gethostbyname(domain_name)
        return True
    except socket.error:
        return False


# Packet capture callback
def packet_callback(packet):
    global frame_count
    if stop_capture_event.is_set():
        return False  # Stop sniffing
    
    # Process only DNS packets
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS request
        dns_query_name = packet[DNSQR].qname.decode("utf-8").strip('.')
        if not is_user_accessed(dns_query_name):  # Ignore non-user-accessed domains
            return
        
        frame_count += 1
        captured_packets.append(packet)  # Store the captured packet
        packet_len = len(packet)
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        protocol = 'DNS'
        src_port = packet[UDP].sport if UDP in packet else "N/A"
        dst_port = packet[UDP].dport if UDP in packet else "N/A"
        capture_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Display packet details in the packet tree
        packet_tree.insert('', 'end', values=(
            f"Frame {frame_count}", capture_time, src_ip, dst_ip, protocol, packet_len, dns_query_name, f"{src_port} -> {dst_port}"
        ), tags=('dns'))
    
    # Process only DNS packets
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS request
        dns_query_name = packet[DNSQR].qname.decode("utf-8").strip('.')
        if not is_user_accessed(dns_query_name):  # Ignore non-user-accessed domains
            return
        
        frame_count += 1
        captured_packets.append(packet)  # Store the captured packet
        packet_len = len(packet)
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        protocol = 'DNS'
        src_port = packet[UDP].sport if UDP in packet else "N/A"
        dst_port = packet[UDP].dport if UDP in packet else "N/A"
        capture_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Display packet details in the packet tree
        packet_tree.insert('', 'end', values=(
            f"Frame {frame_count}", capture_time, src_ip, dst_ip, protocol, packet_len, dns_query_name, f"{src_port} -> {dst_port}"
        ), tags=('dns'))



# Define actions for toolbar buttons
def find_packet():
    search_term = simpledialog.askstring("Find Packet", "Enter search keyword (IP, protocol, or DNS):")
    if search_term:
        found = False
        for item in packet_tree.get_children():
            values = packet_tree.item(item, 'values')
            if any(search_term.lower() in str(value).lower() for value in values):
                packet_tree.selection_set(item)  # Highlight matching packet
                packet_tree.see(item)  # Scroll to the matching packet
                found = True
                break
        if not found:
            messagebox.showinfo("No Match", f"No packets found matching '{search_term}'")

def go_to_previous_packet():
    selected_item = packet_tree.selection()
    if selected_item:
        current_index = packet_tree.index(selected_item)
        if current_index > 0:
            previous_item = packet_tree.get_children()[current_index - 1]
            packet_tree.selection_set(previous_item)
            packet_tree.see(previous_item)  # Scroll to the previous packet
        else:
            messagebox.showinfo("End", "This is the first packet.")

def go_to_next_packet():
    selected_item = packet_tree.selection()
    if selected_item:
        current_index = packet_tree.index(selected_item)
        if current_index < len(packet_tree.get_children()) - 1:
            next_item = packet_tree.get_children()[current_index + 1]
            packet_tree.selection_set(next_item)
            packet_tree.see(next_item)  # Scroll to the next packet
        else:
            messagebox.showinfo("End", "This is the last packet.")

def go_to_first_packet():
    if packet_tree.get_children():
        first_item = packet_tree.get_children()[0]
        packet_tree.selection_set(first_item)
        packet_tree.see(first_item)  # Scroll to the first packet
    else:
        messagebox.showinfo("No Packets", "No packets available.")

def go_to_last_packet():
    if packet_tree.get_children():
        last_item = packet_tree.get_children()[-1]
        packet_tree.selection_set(last_item)
        packet_tree.see(last_item)  # Scroll to the last packet
    else:
        messagebox.showinfo("No Packets", "No packets available.")

def list_network_interfaces(interface_type):
    interfaces = psutil.net_if_addrs()
    packet_list.delete(*packet_list.get_children())  # Clear previous entries

    for interface, addresses in interfaces.items():
        for address in addresses:
            if interface_type == 'All' or \
               (interface_type == 'Wired' and address.family.name == 'AF_INET' and 'Ethernet' in interface) or \
               (interface_type == 'Wireless' and address.family.name == 'AF_INET' and 'Wi-Fi' in interface) or \
               (interface_type == 'External' and 'External' in interface) or \
               (interface_type == 'Hidden' and address.family.name == 'AF_PACKET'):
                packet_list.insert('', 'end', values=(interface, address.family.name, address.address, address.netmask, address.broadcast, address.ptp))

def refresh_interfaces():
    selected_type = interface_type_var.get()
    list_network_interfaces(selected_type)

def clear_packet_details():
    packet_tree.delete(*packet_tree.get_children())

def display_packet_details(event):
    selected_item = packet_list.selection()
    if selected_item:
        item = packet_list.item(selected_item)
        values = item['values']
        details_text = (
            f"Interface: {values[0]}\n"
            f"Address Family: {values[1]}\n"
            f"Address: {values[2]}\n"
            f"Netmask: {values[3]}\n"
            f"Broadcast: {values[4]}\n"
            f"PTP: {values[5]}\n"
        )
        messagebox.showinfo("Interface Details", details_text)

def get_protocol(packet):
    # Filtering only DNS packets
    if DNS in packet:
        return 'DNS'
    else:
        return None

# Helper function to extract DNS query name and ports
def extract_dns_details(packet):
    dns_query_name = ""
    src_port = dst_port = None

    if DNS in packet:
        try:
            dns_query_name = packet[DNS].qd.qname.decode()  # Extract DNS query name (domain being queried)
        except AttributeError:
            dns_query_name = "N/A"

    if UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return dns_query_name, src_port, dst_port

# Global packet callback function for DNS packet processing
def packet_callback(packet):
    global frame_count
    if stop_capture_event.is_set():
        return False  # Stop sniffing
    frame_count += 1
    captured_packets.append(packet)  # Store the captured packet
    packet_len = len(packet)
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        src_ip = 'N/A'
        dst_ip = 'N/A'
    protocol = get_protocol(packet)
    capture_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Only process DNS packets
    if protocol == 'DNS':
        dns_query_name, src_port, dst_port = extract_dns_details(packet)

        # Display relevant DNS packet in the packet tree (with DNS query name and ports)
        packet_tree.insert('', 'end', values=(f"Frame {frame_count}", capture_time, src_ip, dst_ip, protocol, packet_len, f"{dns_query_name}", f"{src_port} -> {dst_port}"), tags=('dns'))

# Function to capture packets
def capture_packets(interface):
    global frame_count
    captured_packets.clear()  # Clear previous captured packets
    frame_count = 0  # Reset frame_count when starting a new capture

    stop_capture_event.clear()  # Reset the event
    packet_tree.delete(*packet_tree.get_children())  # Clear previous content

    try:
        sniff(iface=interface, prn=packet_callback, stop_filter=lambda x: stop_capture_event.is_set())
    except Exception as e:
        messagebox.showerror("Error", f"Packet capture failed: {e}")



# Function to load packets from a file
def load_packets_from_file(file_path):
    global frame_count
    try:
        packets = rdpcap(file_path)
        captured_packets.extend(packets)
        packet_tree.delete(*packet_tree.get_children())  # Clear previous content

        # Set frame_count to the last frame number from the capture (or reset it)
        frame_count = 0  # Reset frame_count before processing new packets
        for packet in packets:
            frame_count += 1  # Continue incrementing frame count
            packet_len = len(packet)
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = 'N/A'
                dst_ip = 'N/A'
            protocol = get_protocol(packet)

            # Only process DNS packets
            if protocol == 'DNS':
                dns_query_name, src_port, dst_port = extract_dns_details(packet)

                capture_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                packet_tree.insert('', 'end', values=(f"Frame {frame_count}", capture_time, src_ip, dst_ip, protocol, packet_len, dns_query_name, f"{src_port} -> {dst_port}"), tags=('dns'))

        messagebox.showinfo("Open", f"Packets loaded from: {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load packets from file: {e}")



def start_capture():
    selected_item = packet_list.selection()
    if selected_item:
        item = packet_list.item(selected_item)
        values = item['values']
        interface = values[0]
        update_status(f"Starting capture on interface: {interface}")  # Update status
        capture_thread = threading.Thread(target=capture_packets, args=(interface,))
        capture_thread.daemon = True  # Allow the thread to exit when the main program exits
        capture_thread.start()

def stop_capture():
    stop_capture_event.set()
    packet_tree.insert('', 'end', values=("Capture Stopped", "", "", "", "", "", "", ""))
    update_status("Packet capture stopped")  # Update status

def continue_capture():
    selected_item = packet_list.selection()
    if selected_item:
        item = packet_list.item(selected_item)
        values = item['values']
        interface = values[0]
        capture_thread = threading.Thread(target=capture_packets, args=(interface,))
        capture_thread.daemon = True
        capture_thread.start()

def on_interface_type_selected(event):
    selected_type = interface_type_var.get()
    list_network_interfaces(selected_type)


# Function to append and display session directories
def update_session_directories(directory):
    session_directories.append(directory)
    status_message = " | ".join(session_directories[-5:])  # Show the last 5 directories for clarity
    update_status(f"Recent Files: {status_message}")


# Update the `open_file` function to update the status bar
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap *.pcapng"), ("All Files", "*.*")])
    if file_path:
        update_status(f"Opening file: {file_path}")  # Temporary status
        load_packets_from_file(file_path)
        update_session_directories(file_path)  # Add to session history
        update_status(f"File opened: {file_path}")  # Confirm file opened


def load_packets_from_file(file_path):
    global frame_count
    try:
        packets = rdpcap(file_path)
        captured_packets.extend(packets)
        packet_tree.delete(*packet_tree.get_children())  # Clear previous content
        for packet in packets:
            frame_count += 1  # Continue incrementing frame count
            packet_len = len(packet)
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = 'N/A'
                dst_ip = 'N/A'
            protocol = get_protocol(packet)

            # Only process DNS packets
            if protocol == 'DNS':
                dns_query_name, src_port, dst_port = extract_dns_details(packet)

                capture_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                packet_tree.insert('', 'end', values=(f"Frame {frame_count}", capture_time, src_ip, dst_ip, protocol, packet_len, dns_query_name, f"{src_port} -> {dst_port}"), tags=('dns'))

        messagebox.showinfo("Open", f"Packets loaded from: {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load packets from file: {e}")

def save_file():
    global save_file_path
    if save_file_path:
        save_packets_to_file(save_file_path)
    else:
        save_as_file()

def save_as_file():
    global save_file_path
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if file_path:
        save_file_path = file_path
        save_packets_to_file(file_path)

# Update the `save_packets_to_file` function to include a status update
def save_packets_to_file(file_path):
    if captured_packets:
        wrpcap(file_path, captured_packets)
        messagebox.showinfo("Save", f"Packets saved to: {file_path}")
        update_session_directories(file_path)  # Add to session history
        update_status(f"File saved: {file_path}")  # Update status
    else:
        messagebox.showwarning("Save", "No packets to save")
        update_status("Save failed: No packets to save")  # Update status

# Function to clear session directories and reset the status bar upon exit
def exit_app():
    global session_directories
    session_directories.clear()  # Clear session history
    update_status("Application closed. Session cleared.")  # Reset status
    app.quit()



# Hover effect function
def on_hover_in(button):
    button.config(bg='#abdcf5')  # Change to light blue on hover

def on_hover_out(button):
    button.config(bg='#f0f0f0')  # Reset to default background color

# Initialize the application
app = tk.Tk()
app.title("Network Monitoring And Analysis Tool")
app.geometry("1100x700")

# Create the menu bar
menu_bar = Menu(app)

# Create the File menu
file_menu = Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Open", command=open_file)
file_menu.add_command(label="Save", command=save_file)
file_menu.add_command(label="Save As", command=save_as_file)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=exit_app)

# Add the File menu to the menu bar
menu_bar.add_cascade(label="File", menu=file_menu)


def show_live_graph():
    # Create a new window for live graphs
    live_graph_window = tk.Toplevel(app)
    live_graph_window.title("Live Network Traffic Graphs")
    live_graph_window.geometry("600x600")  # Adjust window size

    # Scrollable frame for multiple graphs
    scroll_frame = tk.Frame(live_graph_window)
    scroll_frame.pack(fill=tk.BOTH, expand=True)
    
    canvas = tk.Canvas(scroll_frame)
    scrollbar = ttk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Dictionaries for interface tracking
    interface_traffic = {}
    graph_data = {}
    interface_frames = {}  # To track frames for each interface

def show_live_graph():
    # Create a new window for live graphs
    live_graph_window = tk.Toplevel(app)
    live_graph_window.title("Live Network Traffic Graphs")
    live_graph_window.geometry("600x600")  # Adjust window size

    # Scrollable frame for multiple graphs
    scroll_frame = tk.Frame(live_graph_window)
    scroll_frame.pack(fill=tk.BOTH, expand=True)

    # Canvas for the scrollable frame
    canvas = tk.Canvas(scroll_frame)
    scrollbar = ttk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    # Binding for the scrollable frame
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Dictionaries for interface tracking
    interface_traffic = {}  # To track packets
    graph_data = {}  # To store graph data for each interface
    interface_frames = {}  # To store frames (graph canvases) for each interface

    def update_live_graph():
        nonlocal interface_traffic, graph_data
        counters = psutil.net_io_counters(pernic=True)

        for iface, stats in counters.items():
            # Initialize tracking if this is the first time encountering this interface
            if iface not in interface_traffic:
                interface_traffic[iface] = stats.packets_sent + stats.packets_recv
                graph_data[iface] = [0] * 50  # Store 50 points for the graph

                # Create a new frame for this interface
                iface_frame = tk.Frame(scrollable_frame, bd=2, relief=tk.GROOVE, padx=10, pady=5)
                iface_frame.pack(fill=tk.X, pady=10)  # Add padding between graphs
                
                tk.Label(iface_frame, text=f"Interface: {iface}", font=("Arial", 12, "bold")).pack(anchor="w")
                
                # Create a smaller and centered graph canvas for this interface
                graph_canvas = tk.Canvas(iface_frame, width=400, height=150, bg="white")
                graph_canvas.pack(anchor="center", pady=10)  # Center the graph
                
                # Store the canvas in the interface_frames dictionary
                interface_frames[iface] = graph_canvas

            # Calculate packets/sec (network traffic)
            new_traffic = stats.packets_sent + stats.packets_recv
            packets_per_sec = new_traffic - interface_traffic[iface]
            interface_traffic[iface] = new_traffic

            # Update the graph data
            graph_data[iface].append(packets_per_sec)
            graph_data[iface] = graph_data[iface][-50:]  # Keep the last 50 data points

            # Update the graph canvas for this interface
            graph_canvas = interface_frames[iface]
            graph_canvas.delete("all")  # Clear previous drawing
            width = graph_canvas.winfo_width()
            height = graph_canvas.winfo_height()
            max_traffic = max(graph_data[iface]) or 1  # Avoid division by zero

            # Draw X and Y axes
            graph_canvas.create_line(40, 10, 40, height - 10, fill="black", width=1)  # Y-axis
            graph_canvas.create_line(40, height - 10, width - 10, height - 10, fill="black", width=1)  # X-axis

            # Add axis labels
            graph_canvas.create_text(20, height // 2, text="Packets/sec", angle=90, font=("Arial", 10))  # Y-axis label
            graph_canvas.create_text(width // 2, height - 5, text="Time (s)", font=("Arial", 10))  # X-axis label

            # Scale data for the graph and plot it
            scaled_data = [
                (40 + x * (width - 50) // 50, height - 10 - (y * (height - 20) // max_traffic))
                for x, y in enumerate(graph_data[iface])
            ]
            for j in range(len(scaled_data) - 1):
                graph_canvas.create_line(
                    scaled_data[j][0], scaled_data[j][1],
                    scaled_data[j + 1][0], scaled_data[j + 1][1],
                    fill="blue", width=2
                )

            # Add Y-axis ticks (intervals based on max_traffic)
            for i in range(0, max_traffic + 1, max_traffic // 5 if max_traffic >= 5 else 1):
                y_pos = height - 10 - (i * (height - 20) // max_traffic)
                graph_canvas.create_text(30, y_pos, text=str(i), font=("Arial", 8))

            # Add X-axis ticks
            for i in range(0, 51, 10):  # Show 10-point intervals on the X-axis
                x_pos = 40 + i * (width - 50) // 50
                graph_canvas.create_text(x_pos, height - 5, text=str(i), font=("Arial", 8))

        # Schedule the next update in 1 second
        live_graph_window.after(1000, update_live_graph)

    # Start the graph updates
    update_live_graph()


# Add "View" menu
view_menu = Menu(menu_bar, tearoff=0)
view_menu.add_command(label="Show Live Graph", command=show_live_graph)  # Add the "Show Live Graph" menu
menu_bar.add_cascade(label="View", menu=view_menu)

# Function to display history in a dialog
def view_history():
    if session_directories:
        history_message = "\n".join(session_directories)
        messagebox.showinfo("File History", f"Opened/Saved File Directories:\n\n{history_message}")
    else:
        messagebox.showinfo("File History", "No files opened or saved during this session.")

# Function to clear history
def clear_history():
    global session_directories
    session_directories.clear()
    update_status("History cleared.")  # Update status
    messagebox.showinfo("History", "File history has been cleared.")

# Add a History menu
history_menu = Menu(menu_bar, tearoff=0)
history_menu.add_command(label="View History", command=view_history)
history_menu.add_command(label="Clear History", command=clear_history)
menu_bar.add_cascade(label="History", menu=history_menu)

# Set the menu bar for the app
app.config(menu=menu_bar)


# Tooltip function to display text on hover close to the icons
def show_tooltip(event, text, tooltip_label):
    tooltip_label.config(text=text)
    tooltip_label.place(x=event.x_root + 5, y=event.y_root - 35)  # Adjust position close to the icon

def hide_tooltip(tooltip_label):
    tooltip_label.place_forget()

# Add the toolbar frame
toolbar_frame = tk.Frame(app, bg='#ffffff', relief=tk.RAISED, bd=1)
toolbar_frame.pack(fill=tk.X)

# Define actions for toolbar buttons
icons = {
    "find packet": "find_icon.png", 
    "prev packet": "prev_icon.png",
    "next packet": "next_icon.png",
    "first packet": "first_icon.png",
    "last packet": "last_icon.png",
}

commands = [
    ("Find Packet", find_packet, icons["find packet"]),
    ("Previous Packet", go_to_previous_packet, icons["prev packet"]),
    ("Next Packet", go_to_next_packet, icons["next packet"]),
    ("First Packet", go_to_first_packet, icons["first packet"]),
    ("Last Packet", go_to_last_packet, icons["last packet"]),
]


# Create a label for the tooltip (hidden initially)
tooltip_label = tk.Label(app, bg="white", fg="black", font=("Arial", 10), relief=tk.SOLID, bd=1, padx=5, pady=3)
tooltip_label.place_forget()  # Hide the tooltip initially

# Create buttons and bind tooltips
for title, command, icon in commands:
    img = ImageTk.PhotoImage(Image.open(icon).resize((15, 15)))
    btn = tk.Button(toolbar_frame, image=img, command=command, relief=tk.FLAT, bg='#ffffff')
    btn.image = img  # Keep a reference to avoid garbage collection
    btn.pack(side=tk.LEFT, padx=2, pady=2)
    
    # Show tooltip on hover
    btn.bind("<Enter>", lambda e, b=btn, t=title: show_tooltip(e, t, tooltip_label))
    btn.bind("<Leave>", lambda e: hide_tooltip(tooltip_label))

# Continue with the rest of the GUI setup...


# Load icons (ensure icons are in the same directory or provide the correct path)
start_icon = ImageTk.PhotoImage(Image.open("start_icon.png").resize((15, 15)))
stop_icon = ImageTk.PhotoImage(Image.open("stop_icon.png").resize((15, 15)))
continue_icon = ImageTk.PhotoImage(Image.open("continue_icon.png").resize((15, 15)))
clear_icon = ImageTk.PhotoImage(Image.open("clear_icon.png").resize((15, 15)))

# Interface type selection
interface_frame = tk.Frame(app)
interface_frame.pack(fill=tk.X, pady=5)

tk.Label(interface_frame, text="Select Interface Type:").pack(side=tk.LEFT, padx=5)
interface_type_var = tk.StringVar()
interface_type_menu = ttk.Combobox(interface_frame, textvariable=interface_type_var, width=20)
interface_type_menu['values'] = ('All', 'Wired', 'Wireless', 'External', 'Hidden')
interface_type_menu.current(0)
interface_type_menu.bind("<<ComboboxSelected>>", on_interface_type_selected)
interface_type_menu.pack(side=tk.LEFT, padx=5)

refresh_button = tk.Button(interface_frame, text="Refresh Interfaces", command=refresh_interfaces)
refresh_button.pack(side=tk.LEFT, padx=5)

# Capture buttons
button_frame = tk.Frame(app)
button_frame.pack(fill=tk.X, pady=5)

start_button = tk.Button(button_frame, text="Start Capture", image=start_icon, compound="left", command=start_capture)
start_button.pack(side=tk.LEFT, padx=5)
start_button.bind("<Enter>", lambda e: on_hover_in(start_button))
start_button.bind("<Leave>", lambda e: on_hover_out(start_button))

stop_button = tk.Button(button_frame, text="Stop Capture", image=stop_icon, compound="left", command=stop_capture)
stop_button.pack(side=tk.LEFT, padx=5)
stop_button.bind("<Enter>", lambda e: on_hover_in(stop_button))
stop_button.bind("<Leave>", lambda e: on_hover_out(stop_button))

continue_button = tk.Button(button_frame, text="Continue Capture", image=continue_icon, compound="left", command=continue_capture)
continue_button.pack(side=tk.LEFT, padx=5)
continue_button.bind("<Enter>", lambda e: on_hover_in(continue_button))
continue_button.bind("<Leave>", lambda e: on_hover_out(continue_button))

clear_button = tk.Button(button_frame, text="Clear", image=clear_icon, compound="left", command=clear_packet_details)
clear_button.pack(side=tk.LEFT, padx=5)
clear_button.bind("<Enter>", lambda e: on_hover_in(clear_button))
clear_button.bind("<Leave>", lambda e: on_hover_out(clear_button))

# Network interfaces packet list tree view
interface_list_frame = tk.Frame(app)
interface_list_frame.pack(fill=tk.BOTH, expand=True)

packet_list = ttk.Treeview(interface_list_frame, columns=("Interface", "Family", "Address", "Netmask", "Broadcast", "PTP"), show="headings")
packet_list.heading("Interface", text="Interface")
packet_list.heading("Family", text="Family")
packet_list.heading("Address", text="Address")
packet_list.heading("Netmask", text="Netmask")
packet_list.heading("Broadcast", text="Broadcast")
packet_list.heading("PTP", text="PTP")
packet_list.pack(fill=tk.BOTH, expand=True)
packet_list.bind("<Double-1>", display_packet_details)

# Packet capture tree view
packet_tree_frame = tk.Frame(app)
packet_tree_frame.pack(fill=tk.BOTH, expand=True)

packet_tree = ttk.Treeview(packet_tree_frame, columns=("Frame", "Time", "Source IP", "Destination IP", "Protocol", "Length", "DNS Query", "Ports"), show="headings", height=20)  # Increased height
packet_tree.heading("Frame", text="Frame")
packet_tree.heading("Frame", text="Frame")
packet_tree.heading("Time", text="Time")
packet_tree.heading("Source IP", text="Source IP")
packet_tree.heading("Destination IP", text="Destination IP")
packet_tree.heading("Protocol", text="Protocol")
packet_tree.heading("Length", text="Length")
packet_tree.heading("DNS Query", text="DNS Query")
packet_tree.heading("Ports", text="Ports")

packet_tree.tag_configure("dns", background="lightgreen")  # Light green for DNS packets
packet_tree.pack(fill=tk.BOTH, expand=True)

# Add this near the end of your GUI setup, before `app.mainloop()`
status_bar = tk.Label(app, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, height=1)  # Increased height
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Function to update the status bar
def update_status(message):
    status_bar.config(text=message)

# Run the application
app.mainloop()

