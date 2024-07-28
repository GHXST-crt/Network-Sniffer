import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import sniff, wrpcap, rdpcap
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from dpi_module import DPI
from packet_reassembly import PacketReassembler
from advanced_filtering import AdvancedFiltering
from protocol_decoding import ProtocolDecoding
from bottleneck_tracking import BottleneckTracking
from firewall_testing import FirewallTesting
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')

        self.packets = []
        self.dpi = DPI()
        self.reassembler = PacketReassembler()
        self.filtering = AdvancedFiltering()
        self.decoder = ProtocolDecoding()
        self.bottleneck_tracker = BottleneckTracking()
        self.firewall_tester = FirewallTesting()

        self.create_widgets()
        self.sniffing_thread = None
        self.running = False

    def create_widgets(self):
        self.create_menu()
        self.create_toolbar()
        self.create_main_area()
        self.create_status_bar()

    def create_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Start Sniffing", command=self.start_sniffing)
        file_menu.add_command(label="Stop Sniffing", command=self.stop_sniffing)
        file_menu.add_separator()
        file_menu.add_command(label="Save Packets", command=self.save_packets)
        file_menu.add_command(label="Import Packets", command=self.import_packets)
        file_menu.add_command(label="Export Packets", command=self.export_packets)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        analysis_menu = tk.Menu(menubar, tearoff=0)
        analysis_menu.add_command(label="Deep Packet Inspection", command=self.deep_packet_inspection)
        analysis_menu.add_command(label="Packet Reassembly", command=self.packet_reassembly)
        analysis_menu.add_command(label="Track Network Bottlenecks", command=self.track_bottlenecks)
        analysis_menu.add_command(label="Test Firewall Efficacy", command=self.test_firewalls)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Settings", command=self.open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Advanced Filtering", command=self.advanced_filtering)
        tools_menu.add_command(label="Protocol Decoding", command=self.protocol_decoding)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        self.root.config(menu=menubar)

    def create_toolbar(self):
        toolbar = tk.Frame(self.root, bd=1, relief=tk.RAISED, bg='#2b2b2b')
        start_btn = tk.Button(toolbar, text="Start Sniffing", command=self.start_sniffing, bg='#5c5c5c', fg='white')
        start_btn.pack(side=tk.LEFT, padx=2, pady=2)
        stop_btn = tk.Button(toolbar, text="Stop Sniffing", command=self.stop_sniffing, bg='#5c5c5c', fg='white')
        stop_btn.pack(side=tk.LEFT, padx=2, pady=2)
        export_btn = tk.Button(toolbar, text="Export Packets", command=self.export_packets, bg='#5c5c5c', fg='white')
        export_btn.pack(side=tk.LEFT, padx=2, pady=2)
        toolbar.pack(side=tk.TOP, fill=tk.X)

    def create_main_area(self):
        self.packet_list = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=20, bg='#2b2b2b', fg='white', font=('Courier', 12))
        self.packet_list.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

    def create_status_bar(self):
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='#2b2b2b', fg='white')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.sniffing_thread = threading.Thread(target=self.sniff_packets)
            self.sniffing_thread.start()
            self.status_bar.config(text="Sniffing started...")

    def stop_sniffing(self):
        self.running = False
        if self.sniffing_thread:
            self.sniffing_thread.join()
            self.sniffing_thread = None
        self.status_bar.config(text="Sniffing stopped.")

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, timeout=1)

    def packet_callback(self, packet):
        self.packets.append(packet)
        self.packet_list.insert(tk.END, f"{packet.summary()}\n")
        self.packet_list.see(tk.END)

    def save_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("Packet Sniffer", f"Packets saved to {file_path}")

    def import_packets(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            self.packets = rdpcap(file_path)
            self.packet_list.delete('1.0', tk.END)
            for packet in self.packets:
                self.packet_list.insert(tk.END, f"{packet.summary()}\n")
            messagebox.showinfo("Packet Sniffer", f"Packets imported from {file_path}")

    def export_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("Packet Sniffer", f"Packets exported to {file_path}")

    def deep_packet_inspection(self):
        dpi_window = tk.Toplevel(self.root)
        dpi_window.title("Deep Packet Inspection")
        dpi_window.geometry("800x600")
        dpi_window.configure(bg='#1e1e1e')

        dpi_text = scrolledtext.ScrolledText(dpi_window, wrap=tk.WORD, height=30, bg='#2b2b2b', fg='white', font=('Courier', 12))
        dpi_text.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

        for packet in self.packets:
            analysis = self.dpi.analyze_packet(packet)
            dpi_text.insert(tk.END, f"Packet: {packet}\n")
            for key, value in analysis.items():
                dpi_text.insert(tk.END, f"{key}: {value}\n")
            dpi_text.insert(tk.END, "-" * 50 + "\n")
        dpi_text.see(tk.END)

    def packet_reassembly(self):
        reassembly_window = tk.Toplevel(self.root)
        reassembly_window.title("Packet Reassembly")
        reassembly_window.geometry("800x600")
        reassembly_window.configure(bg='#1e1e1e')

        reassembly_text = scrolledtext.ScrolledText(reassembly_window, wrap=tk.WORD, height=30, bg='#2b2b2b', fg='white', font=('Courier', 12))
        reassembly_text.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

        for packet in self.packets:
            reassembled_packet = self.reassembler.reassemble(packet)
            if reassembled_packet:
                reassembly_text.insert(tk.END, f"Reassembled Packet: {reassembled_packet}\n")
                reassembly_text.insert(tk.END, "-" * 50 + "\n")
        reassembly_text.see(tk.END)

    def track_bottlenecks(self):
        bottleneck_window = tk.Toplevel(self.root)
        bottleneck_window.title("Track Network Bottlenecks")
        bottleneck_window.geometry("800x600")
        bottleneck_window.configure(bg='#1e1e1e')

        bottleneck_text = scrolledtext.ScrolledText(bottleneck_window, wrap=tk.WORD, height=30, bg='#2b2b2b', fg='white', font=('Courier', 12))
        bottleneck_text.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

        bottleneck_data = self.bottleneck_tracker.track(self.packets)
        for entry in bottleneck_data:
            bottleneck_text.insert(tk.END, f"{entry}\n")
        bottleneck_text.see(tk.END)

    def test_firewalls(self):
        firewall_window = tk.Toplevel(self.root)
        firewall_window.title("Test Firewall Efficacy")
        firewall_window.geometry("800x600")
        firewall_window.configure(bg='#1e1e1e')

        firewall_text = scrolledtext.ScrolledText(firewall_window, wrap=tk.WORD, height=30, bg='#2b2b2b', fg='white', font=('Courier', 12))
        firewall_text.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

        firewall_data = self.firewall_tester.test(self.packets)
        for entry in firewall_data:
            firewall_text.insert(tk.END, f"{entry}\n")
        firewall_text.see(tk.END)

    def advanced_filtering(self):
        filtering_window = tk.Toplevel(self.root)
        filtering_window.title("Advanced Filtering")
        filtering_window.geometry("800x600")
        filtering_window.configure(bg='#1e1e1e')

        filter_text = scrolledtext.ScrolledText(filtering_window, wrap=tk.WORD, height=30, bg='#2b2b2b', fg='white', font=('Courier', 12))
        filter_text.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

        filter_data = self.filtering.filter(self.packets)
        for entry in filter_data:
            filter_text.insert(tk.END, f"{entry}\n")
        filter_text.see(tk.END)

    def protocol_decoding(self):
        decoding_window = tk.Toplevel(self.root)
        decoding_window.title("Protocol Decoding")
        decoding_window.geometry("800x600")
        decoding_window.configure(bg='#1e1e1e')

        decoding_text = scrolledtext.ScrolledText(decoding_window, wrap=tk.WORD, height=30, bg='#2b2b2b', fg='white', font=('Courier', 12))
        decoding_text.pack(fill=tk.BOTH, expand=1, padx=10, pady=10)

        decode_data = self.decoder.decode(self.packets)
        for entry in decode_data:
            decoding_text.insert(tk.END, f"{entry}\n")
        decoding_text.see(tk.END)

    def open_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x400")
        settings_window.configure(bg='#1e1e1e')

        settings_label = tk.Label(settings_window, text="Settings will be available soon.", bg='#1e1e1e', fg='white', font=('Arial', 14))
        settings_label.pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
