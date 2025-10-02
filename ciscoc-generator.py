import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, Toplevel
import datetime
from jinja2 import Environment
from ttkthemes import ThemedTk
import os

# --- JINJA2 SABLON A KÓDBA ÁGYAZVA ---
# A router_config.j2 fájl tartalma itt van, egyetlen szöveges változóként.
ROUTER_TEMPLATE_STRING = """
! =================================================================
! Konfiguráció generálva: {{ current_time }}
! Forrás: Profi Cisco Generátor
! =================================================================
!
! --- 1. ALAPBEÁLLÍTÁSOK ÉS BIZTONSÁGI MEGERŐSÍTÉSEK ---
!
hostname {{ hostname }}
!
no ip domain lookup
!
{% if enable_secret %}enable secret {{ enable_secret }}{% endif %}
!
{% if sec_pwd_encrypt %}service password-encryption{% endif %}
!
{% if sec_no_http %}
no ip http server
no ip http secure-server
{% endif %}
!
{% if domain_name %}
ip domain-name {{ domain_name }}
crypto key generate rsa modulus 2048
{% endif %}
!
{% if banner_motd %}
banner motd #
{{ banner_motd }}
#
{% endif %}
!
! --- 2. FELHASZNÁLÓK ÉS VTY VONALAK ---
!
{% if vty_user and vty_pass %}username {{ vty_user }} privilege 15 secret {{ vty_pass }}{% endif %}
!
line con 0
 password cisco
 login
{% if sec_log_sync %} logging synchronous{% endif %}
 exec-timeout 15 0
!
line vty 0 4
 transport input ssh
 login local
{% if vty_acl %} access-class {{ vty_acl }} in{% endif %}
 exec-timeout 15 0
!
! --- 3. VLAN ADATBÁZIS ---
!
{% if vlans %}
!
{% for vlan in vlans %}
vlan {{ vlan.id }}
 name {{ vlan.name }}
{% endfor %}
!
{% endif %}
!
! --- 4. INTERFÉSZ KONFIGURÁCIÓ ---
!
{% for iface in interfaces %}
interface {{ iface.name }}
{% if iface.desc %} description {{ iface.desc }}{% endif %}
{% if iface.ip_mask %} ip address {{ iface.ip_mask }}{% endif %}
!
{% if hairpin_nat_enabled and (iface.nat_inside or iface.nat_outside) %}
 ip nat enable
{% else %}
{% if iface.nat_inside %} ip nat inside{% endif %}
{% if iface.nat_outside %} ip nat outside{% endif %}
{% endif %}
!
{% if iface.no_shut %} no shutdown{% else %} shutdown{% endif %}
!
{% endfor %}
!
! --- 5. FORGALOMIRÁNYÍTÁS (ROUTING) ---
!
ip routing
!
{% if static_routes %}
! Statikus útvonalak
{% for route in static_routes %}
ip route {{ route.dest }} {{ route.mask }} {{ route.next_hop }}
{% endfor %}
!
{% endif %}
!
{% if ospf_enabled %}
router ospf {{ ospf_pid }}
 router-id {{ ospf_rid }}
{% for network in ospf_networks.split('\n') if network.strip() %}
 network {{ network }}
{% endfor %}
{% for p_iface in ospf_passive.split('\n') if p_iface.strip() %}
 passive-interface {{ p_iface }}
{% endfor %}
!
{% endif %}
!
{% if eigrp_enabled %}
router eigrp {{ eigrp_as }}
{% for network in eigrp_networks.split('\n') if network.strip() %}
 network {{ network }}
{% endfor %}
 no auto-summary
!
{% endif %}
!
{% if bgp_enabled %}
router bgp {{ bgp_as }}
 bgp log-neighbor-changes
{% for neighbor in bgp_neighbors.split('\n') if neighbor.strip() %}
 neighbor {{ neighbor }}
{% endfor %}
!
{% endif %}
!
! --- 6. NAT (NETWORK ADDRESS TRANSLATION) ---
!
{% if pat_enabled and pat_acl and pat_outside_if and not hairpin_nat_enabled %}
ip nat inside source list {{ pat_acl }} interface {{ pat_outside_if }} overload
!
{% endif %}
!
{% if static_nat_data %}
! Statikus 1:1 NAT leképezések
{% for nat in static_nat_data %}
ip nat inside source static {{ nat.inside_ip }} {{ nat.outside_ip }}
{% endfor %}
!
{% endif %}
!
{% if port_fwd_data and pat_outside_if %}
! Port Forwarding szabályok
{% for fwd in port_fwd_data %}
ip nat inside source static {{ fwd.proto }} {{ fwd.inside_ip }} {{ fwd.inside_port }} interface {{ pat_outside_if }} {{ fwd.outside_port }}
{% endfor %}
!
{% endif %}
!
! --- 7. SITE-TO-SITE VPN (IKEv2 + VTI) ---
!
{% if vpn_enabled %}
! --- IKEv2 Konfiguráció ---
crypto ikev2 proposal IKE-PROPOSAL-{{ vpn_tunnel_id }}
 {{ vpn_ike_proposal }}
!
crypto ikev2 policy IKE-POLICY-{{ vpn_tunnel_id }}
 proposal IKE-PROPOSAL-{{ vpn_tunnel_id }}
!
crypto ikev2 keyring IKE-KEYRING-{{ vpn_tunnel_id }}
 peer {{ vpn_peer_ip }}
  address {{ vpn_peer_ip }}
  pre-shared-key {{ vpn_psk }}
 !
!
crypto ikev2 profile IKE-PROFILE-{{ vpn_tunnel_id }}
 match address local interface {{ vpn_tunnel_source }}
 match identity remote address {{ vpn_peer_ip }}
 authentication remote pre-share
 authentication local pre-share
 keyring local IKE-KEYRING-{{ vpn_tunnel_id }}
!
! --- IPsec Konfiguráció ---
crypto ipsec transform-set IPSEC-TRANSFORM-{{ vpn_tunnel_id }}
 {{ vpn_ipsec_transform }}
 mode tunnel
!
crypto ipsec profile IPSEC-PROFILE-{{ vpn_tunnel_id }}
 set transform-set IPSEC-TRANSFORM-{{ vpn_tunnel_id }}
 set ikev2-profile IKE-PROFILE-{{ vpn_tunnel_id }}
!
! --- VTI (Virtual Tunnel Interface) Konfiguráció ---
interface Tunnel{{ vpn_tunnel_id }}
 description VPN Tunnel to Peer {{ vpn_peer_ip }}
 ip address {{ vpn_tunnel_ip }}
 ip mtu 1400
 ip tcp adjust-mss 1360
 tunnel source {{ vpn_tunnel_source }}
 tunnel mode ipsec ipv4
 tunnel destination {{ vpn_peer_ip }}
 tunnel protection ipsec profile IPSEC-PROFILE-{{ vpn_tunnel_id }}
!
! --- VPN Forgalomirányítás ---
ip route {{ vpn_remote_net }} {{ vpn_remote_mask }} Tunnel{{ vpn_tunnel_id }}
!
{% endif %}
!
! --- 8. ACL (ACCESS CONTROL LISTS) ---
!
{% if acls %}
!
{% for name, acl in acls.items() %}
{% if acl.type == 'standard' %}
ip access-list standard {{ name }}
{% for rule in acl.rules %}
 {{ rule.action }} {{ rule.src }}
{% endfor %}
{% elif acl.type == 'extended' %}
ip access-list extended {{ name }}
{% for rule in acl.rules %}
 {{ rule.action }} {{ rule.proto }} {{ rule.src }} {{ rule.dst }}{% if rule.port %} {{ rule.port }}{% endif %}
{% endfor %}
{% endif %}
!
{% endfor %}
{% endif %}
!
! --- 9. MENEDZSMENT & MONITORING ---
!
{% if snmp_enabled %}
{% if snmp_community_ro %}snmp-server community {{ snmp_community_ro }} RO{% endif %}
{% if snmp_location %}snmp-server location {{ snmp_location }}{% endif %}
{% if snmp_contact %}snmp-server contact {{ snmp_contact }}{% endif %}
!
{% endif %}
!
{% if syslog_host %}
logging host {{ syslog_host }}
logging trap informational
!
{% endif %}
!
{% if ntp_servers %}
{% for server in ntp_servers.split('\n') if server.strip() %}
ntp server {{ server }}
{% endfor %}
!
{% endif %}
!
! --- Konfiguráció Vége ---
!
end
"""


# --- FŐ GUI OSZTÁLY ---

class CiscoConfigApp(ThemedTk):
    def __init__(self):
        super().__init__()
        self.set_theme("sun-valley")
        self.title("Profi Cisco Generátor (NAT, VPN, Security) - Standalone")
        self.geometry("1300x950")

        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
        except Exception:
            print("Ikon (icon.ico) nem található, vagy a beállítás nem támogatott.")

        self.interfaces_data = []
        self.vlans_data = []
        self.static_routes_data = []
        self.acls_data = {}
        self.static_nat_data = []
        self.port_fwd_data = []
        self.text_widgets = {}

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.setup_variables()

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(pady=5, padx=5, expand=True, fill="both")
        
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill="both", expand=True, padx=5, pady=(5, 10))

        preview_frame = ttk.LabelFrame(bottom_frame, text="Generált Konfiguráció Előnézete")
        preview_frame.pack(fill="both", expand=True, pady=5)
        self.preview_text = tk.Text(preview_frame, wrap='word', height=15, font=("Courier New", 10), relief=tk.FLAT)
        
        scrollbar = ttk.Scrollbar(preview_frame, command=self.preview_text.yview, style='Vertical.TScrollbar')
        self.preview_text.config(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill='y')
        self.preview_text.pack(fill="both", expand=True, side=tk.LEFT, padx=5, pady=5)

        button_frame = ttk.Frame(bottom_frame)
        button_frame.pack(fill='x', pady=5)
        ttk.Button(button_frame, text="1. Előnézet Generálása", command=self.generate_preview, style='Accent.TButton').pack(side=tk.LEFT, padx=5, ipady=4)
        ttk.Button(button_frame, text="2. Konfiguráció Mentése Fájlba (.txt)", command=self.generate_and_save).pack(side=tk.LEFT, padx=5, ipady=4)
        ttk.Button(button_frame, text="Kilépés", command=self.quit).pack(side=tk.RIGHT, padx=5, ipady=4)
        
        self.create_tabs()

    def setup_variables(self):
        self.vars = {
            'hostname': tk.StringVar(value="CGR-HQ-FW-01"), 'enable_secret': tk.StringVar(value="cisco"),
            'vty_user': tk.StringVar(value="netadmin"), 'vty_pass': tk.StringVar(value="cisco123"), 'vty_acl': tk.StringVar(value="VTY_ACL"),
            'domain_name': tk.StringVar(value="corporate.local"), 'banner_motd': tk.StringVar(value="!!! Unauthorized Access is Strictly Prohibited !!!"),
            'sec_pwd_encrypt': tk.BooleanVar(value=True), 'sec_no_http': tk.BooleanVar(value=True), 'sec_log_sync': tk.BooleanVar(value=True),
            'ospf_enabled': tk.BooleanVar(value=False), 'ospf_pid': tk.StringVar(value="1"), 'ospf_rid': tk.StringVar(value="1.1.1.1"),
            'eigrp_enabled': tk.BooleanVar(value=False), 'eigrp_as': tk.StringVar(value="100"),
            'bgp_enabled': tk.BooleanVar(value=False), 'bgp_as': tk.StringVar(value="65001"),
            'pat_enabled': tk.BooleanVar(value=True), 'pat_outside_if': tk.StringVar(value="GigabitEthernet0/0"), 'pat_acl': tk.StringVar(value="NAT_TRAFFIC_ACL"),
            'hairpin_nat_enabled': tk.BooleanVar(value=False),
            'snmp_enabled': tk.BooleanVar(value=True), 'snmp_community_ro': tk.StringVar(value="RO-Community"),
            'snmp_location': tk.StringVar(value="Budapest HQ"), 'snmp_contact': tk.StringVar(value="noc@corporate.local"),
            'syslog_host': tk.StringVar(value="10.254.1.10"),
            'vpn_enabled': tk.BooleanVar(value=False), 'vpn_tunnel_id': tk.StringVar(value="10"), 'vpn_tunnel_ip': tk.StringVar(value="169.254.10.1 255.255.255.252"),
            'vpn_tunnel_source': tk.StringVar(value="GigabitEthernet0/0"), 'vpn_peer_ip': tk.StringVar(value="2.2.2.2"),
            'vpn_psk': tk.StringVar(value="S3cr3tVpnK3y!"), 'vpn_remote_net': tk.StringVar(value="192.168.20.0"), 'vpn_remote_mask': tk.StringVar(value="255.255.255.0"),
            'vpn_ike_proposal': tk.StringVar(value="encryption aes-gcm-256 integrity sha384 prf sha384 group 20"),
            'vpn_ipsec_transform': tk.StringVar(value="esp-gcm 256"),
        }
    
    def create_tabs(self):
        tab_names = ["Alapbeállítások", "Interfészek & VLAN", "Routing", "ACL & Filtering", "NAT & Port Forwarding", "VPN (IPsec)", "Menedzsment"]
        for name in tab_names:
            tab = ttk.Frame(self.notebook, padding="10")
            self.notebook.add(tab, text=name)
            if name == "Alapbeállítások": self.setup_base_config_tab(tab)
            elif name == "Interfészek & VLAN": self.setup_interface_tab(tab)
            elif name == "Routing": self.setup_routing_tab(tab)
            elif name == "ACL & Filtering": self.setup_acl_tab(tab)
            elif name == "NAT & Port Forwarding": self.setup_nat_tab(tab)
            elif name == "VPN (IPsec)": self.setup_vpn_tab(tab)
            elif name == "Menedzsment": self.setup_management_tab(tab)
    
    def setup_base_config_tab(self, tab):
        frame1 = ttk.LabelFrame(tab, text="Alapvető Eszköz Információk", padding=10); frame1.pack(fill='x', expand=True, pady=5)
        ttk.Label(frame1, text="Hostname:").grid(row=0, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame1, textvariable=self.vars['hostname'], width=40).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame1, text="Enable Secret:").grid(row=1, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame1, textvariable=self.vars['enable_secret'], show="*").grid(row=1, column=1, sticky='ew')
        ttk.Label(frame1, text="Banner MOTD:").grid(row=2, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame1, textvariable=self.vars['banner_motd'], width=40).grid(row=2, column=1, sticky='ew')
        frame2 = ttk.LabelFrame(tab, text="SSH Hozzáférés", padding=10); frame2.pack(fill='x', expand=True, pady=10)
        ttk.Label(frame2, text="Admin Felhasználó:").grid(row=0, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['vty_user']).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame2, text="Admin Jelszó:").grid(row=1, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['vty_pass'], show="*").grid(row=1, column=1, sticky='ew')
        ttk.Label(frame2, text="VTY Hozzáférési Lista (ACL):").grid(row=2, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['vty_acl']).grid(row=2, column=1, sticky='ew')
        self.add_explanation(frame2, "Az itt megadott ACL fogja szűrni, hogy mely IP címekről engedélyezett az SSH hozzáférés.", (2,2))
        ttk.Label(frame2, text="Domain Név:").grid(row=3, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['domain_name']).grid(row=3, column=1, sticky='ew')
        self.add_explanation(frame2, "Szükséges az RSA kulcs generálásához, ami az SSH előfeltétele.", (3,2))
        frame3 = ttk.LabelFrame(tab, text="Biztonsági Alapbeállítások (Hardening)", padding=10); frame3.pack(fill='x', expand=True, pady=10)
        ttk.Checkbutton(frame3, text="`service password-encryption`", variable=self.vars['sec_pwd_encrypt']).pack(anchor='w')
        ttk.Checkbutton(frame3, text="`no ip http server`", variable=self.vars['sec_no_http']).pack(anchor='w')
        ttk.Checkbutton(frame3, text="`logging synchronous`", variable=self.vars['sec_log_sync']).pack(anchor='w')

    def setup_interface_tab(self, tab):
        iface_frame = ttk.LabelFrame(tab, text="Interfészek", padding=10); iface_frame.pack(fill="both", expand=True, side=tk.LEFT, padx=5, pady=5)
        cols = ("Név", "IP Cím/Maszk", "Leírás", "Állapot", "NAT"); self.iface_tree = ttk.Treeview(iface_frame, columns=cols, show='headings')
        for col in cols: self.iface_tree.heading(col, text=col); self.iface_tree.column(col, width=120)
        self.iface_tree.pack(fill="both", expand=True)
        btn_frame = ttk.Frame(iface_frame); btn_frame.pack(fill='x', pady=5)
        ttk.Button(btn_frame, text="Hozzáadás", command=self.add_interface).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Módosítás", command=self.edit_interface).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Törlés", command=self.remove_interface).pack(side=tk.LEFT)
        vlan_frame = ttk.LabelFrame(tab, text="VLAN Adatbázis", padding=10); vlan_frame.pack(fill="y", side=tk.RIGHT, padx=5, pady=5)
        vlan_cols = ("ID", "Név"); self.vlan_tree = ttk.Treeview(vlan_frame, columns=vlan_cols, show='headings', height=5)
        self.vlan_tree.heading("ID", text="VLAN ID"); self.vlan_tree.column("ID", width=60); self.vlan_tree.heading("Név", text="VLAN Név"); self.vlan_tree.pack(fill="both", expand=True)
        vlan_btn_frame = ttk.Frame(vlan_frame); vlan_btn_frame.pack(fill='x', pady=5)
        ttk.Button(vlan_btn_frame, text="Új VLAN", command=self.add_vlan).pack(side=tk.LEFT)
        ttk.Button(vlan_btn_frame, text="Törlés", command=self.remove_vlan).pack(side=tk.LEFT, padx=5)
        self.add_explanation(vlan_frame, "Az IP címet (SVI) az Interfészeknél add hozzá 'VLAN' típusként.", grid_pos=None)

    def setup_routing_tab(self, tab):
        routing_notebook = ttk.Notebook(tab); routing_notebook.pack(fill="both", expand=True, pady=5)
        tabs = {"OSPF": self.setup_ospf_tab, "EIGRP": self.setup_eigrp_tab, "BGP": self.setup_bgp_tab, "Statikus": self.setup_static_route_tab}
        for name, setup_func in tabs.items(): t = ttk.Frame(routing_notebook, padding=10); routing_notebook.add(t, text=name); setup_func(t)

    def setup_ospf_tab(self, tab):
        ttk.Checkbutton(tab, text="OSPF Engedélyezése", variable=self.vars['ospf_enabled']).grid(row=0, columnspan=2, sticky='w')
        ttk.Label(tab, text="Process ID:").grid(row=1, column=0, sticky='w', pady=2); ttk.Entry(tab, textvariable=self.vars['ospf_pid']).grid(row=1, column=1, sticky='ew')
        ttk.Label(tab, text="Router ID:").grid(row=2, column=0, sticky='w', pady=2); ttk.Entry(tab, textvariable=self.vars['ospf_rid']).grid(row=2, column=1, sticky='ew')
        ttk.Label(tab, text="Network parancsok (egy/sor):").grid(row=3, column=0, sticky='nw', pady=2); self.text_widgets['ospf_networks'] = tk.Text(tab, height=5, width=40); self.text_widgets['ospf_networks'].grid(row=3, column=1, sticky='ew')
        ttk.Label(tab, text="Passzív interfészek (egy/sor):").grid(row=4, column=0, sticky='nw', pady=2); self.text_widgets['ospf_passive'] = tk.Text(tab, height=3, width=40); self.text_widgets['ospf_passive'].grid(row=4, column=1, sticky='ew')
    
    def setup_eigrp_tab(self, tab):
        ttk.Checkbutton(tab, text="EIGRP Engedélyezése", variable=self.vars['eigrp_enabled']).grid(row=0, columnspan=2, sticky='w')
        ttk.Label(tab, text="AS Szám:").grid(row=1, column=0, sticky='w', pady=2); ttk.Entry(tab, textvariable=self.vars['eigrp_as']).grid(row=1, column=1, sticky='ew')
        ttk.Label(tab, text="Network parancsok (egy/sor):").grid(row=2, column=0, sticky='nw', pady=2); self.text_widgets['eigrp_networks'] = tk.Text(tab, height=5, width=40); self.text_widgets['eigrp_networks'].grid(row=2, column=1, sticky='ew')

    def setup_bgp_tab(self, tab):
        ttk.Checkbutton(tab, text="BGP Engedélyezése", variable=self.vars['bgp_enabled']).grid(row=0, columnspan=2, sticky='w')
        ttk.Label(tab, text="Lokális AS Szám:").grid(row=1, column=0, sticky='w', pady=2); ttk.Entry(tab, textvariable=self.vars['bgp_as']).grid(row=1, column=1, sticky='ew')
        ttk.Label(tab, text="Neighbor parancsok (egy/sor):").grid(row=2, column=0, sticky='nw', pady=2); self.text_widgets['bgp_neighbors'] = tk.Text(tab, height=5, width=40); self.text_widgets['bgp_neighbors'].grid(row=2, column=1, sticky='ew')
        
    def setup_static_route_tab(self, tab):
        frame = ttk.LabelFrame(tab, text="Statikus Útvonalak", padding=10); frame.pack(fill="both", expand=True)
        cols = ("Célhálózat", "Maszk", "Következő Ugrás"); self.static_tree = ttk.Treeview(frame, columns=cols, show='headings')
        for col in cols: self.static_tree.heading(col, text=col)
        self.static_tree.pack(fill='both', expand=True)
        btn_frame = ttk.Frame(frame); btn_frame.pack(fill='x', pady=5)
        ttk.Button(btn_frame, text="Hozzáadás", command=self.add_static_route).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Törlés", command=self.remove_static_route).pack(side=tk.LEFT, padx=5)

    def setup_acl_tab(self, tab):
        acl_frame = ttk.LabelFrame(tab, text="Access Control Lists (ACL)", padding=10); acl_frame.pack(fill='both', expand=True, pady=5)
        list_frame = ttk.Frame(acl_frame); list_frame.pack(side=tk.LEFT, fill='y', padx=5)
        ttk.Label(list_frame, text="ACL-ek:").pack(anchor='w'); self.acl_listbox = tk.Listbox(list_frame, exportselection=False)
        self.acl_listbox.pack(fill='y', expand=True); self.acl_listbox.bind("<<ListboxSelect>>", self.on_acl_select)
        btn_frame = ttk.Frame(list_frame); btn_frame.pack(fill='x')
        ttk.Button(btn_frame, text="Új ACL", command=self.add_acl).pack(fill='x'); ttk.Button(btn_frame, text="Törlés", command=self.remove_acl).pack(fill='x')
        rules_frame = ttk.Frame(acl_frame); rules_frame.pack(side=tk.RIGHT, fill='both', expand=True)
        ttk.Label(rules_frame, text="Kiválasztott ACL Szabályai:").pack(anchor='w')
        cols = ("Sor", "Művelet", "Protokoll", "Forrás", "Cél", "Port"); self.acl_tree = ttk.Treeview(rules_frame, columns=cols, show='headings')
        for col in cols: self.acl_tree.heading(col, text=col); self.acl_tree.column(col, width=100)
        self.acl_tree.pack(fill='both', expand=True)
        rule_btn_frame = ttk.Frame(rules_frame); rule_btn_frame.pack(fill='x', pady=5)
        ttk.Button(rule_btn_frame, text="Új Szabály", command=self.add_acl_rule).pack(side=tk.LEFT)
        ttk.Button(rule_btn_frame, text="Szabály Törlése", command=self.remove_acl_rule).pack(side=tk.LEFT, padx=5)

    def setup_nat_tab(self, tab):
        nat_notebook = ttk.Notebook(tab); nat_notebook.pack(fill="both", expand=True, pady=5)
        tabs = {"PAT (Túlterheléses)": self.setup_pat_tab, "Statikus 1:1 NAT": self.setup_static_nat_tab, "Port Forwarding": self.setup_portfwd_tab}
        for name, setup_func in tabs.items(): t = ttk.Frame(nat_notebook, padding=10); nat_notebook.add(t, text=name); setup_func(t)

    def setup_pat_tab(self, tab):
        frame1 = ttk.LabelFrame(tab, text="Dinamikus NAT (PAT)", padding=10); frame1.pack(fill='x', expand=True, pady=5)
        ttk.Checkbutton(frame1, text="PAT Engedélyezése", variable=self.vars['pat_enabled']).grid(row=0, columnspan=2, sticky='w')
        ttk.Label(frame1, text="Külső (Outside) Interfész:").grid(row=1, column=0, sticky='w'); ttk.Entry(frame1, textvariable=self.vars['pat_outside_if']).grid(row=1, column=1, sticky='ew')
        ttk.Label(frame1, text="Fordítandó forgalom (ACL neve):").grid(row=2, column=0, sticky='w'); ttk.Entry(frame1, textvariable=self.vars['pat_acl']).grid(row=2, column=1, sticky='ew')
        frame2 = ttk.LabelFrame(tab, text="Általános NAT beállítások", padding=10); frame2.pack(fill='x', expand=True, pady=10)
        ttk.Checkbutton(frame2, text="Hairpin NAT engedélyezése (NVI-alapú)", variable=self.vars['hairpin_nat_enabled']).pack(anchor='w')
        self.add_explanation(frame2, "Lehetővé teszi, hogy a belső hálózatról is a külső IP címen keresztül érjék el a port forwardolt szervereket.", grid_pos=None)

    def setup_static_nat_tab(self, tab):
        frame = ttk.LabelFrame(tab, text="1:1 NAT Leképezések", padding=10); frame.pack(fill="both", expand=True)
        cols = ("Belső Lokális IP", "Külső Globális IP"); self.static_nat_tree = ttk.Treeview(frame, columns=cols, show='headings')
        for col in cols: self.static_nat_tree.heading(col, text=col)
        self.static_nat_tree.pack(fill='both', expand=True)
        btn_frame = ttk.Frame(frame); btn_frame.pack(fill='x', pady=5)
        ttk.Button(btn_frame, text="Hozzáadás", command=self.add_static_nat).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Törlés", command=self.remove_static_nat).pack(side=tk.LEFT, padx=5)
        
    def setup_portfwd_tab(self, tab):
        frame = ttk.LabelFrame(tab, text="Port Átirányítási Szabályok", padding=10); frame.pack(fill="both", expand=True)
        cols = ("Protokoll", "Belső IP", "Belső Port", "Külső Port"); self.port_fwd_tree = ttk.Treeview(frame, columns=cols, show='headings')
        for col in cols: self.port_fwd_tree.heading(col, text=col)
        self.port_fwd_tree.pack(fill='both', expand=True)
        btn_frame = ttk.Frame(frame); btn_frame.pack(fill='x', pady=5)
        ttk.Button(btn_frame, text="Hozzáadás", command=self.add_port_fwd).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Törlés", command=self.remove_port_fwd).pack(side=tk.LEFT, padx=5)

    def setup_vpn_tab(self, tab):
        ttk.Checkbutton(tab, text="Site-to-Site VPN Engedélyezése", variable=self.vars['vpn_enabled']).pack(anchor='w', pady=5)
        frame1 = ttk.LabelFrame(tab, text="I. Kapcsolat Adatok", padding=10); frame1.pack(fill='x', expand=True, pady=5)
        ttk.Label(frame1, text="Távoli Peer IP Címe:").grid(row=0, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame1, textvariable=self.vars['vpn_peer_ip'], width=40).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame1, text="Előre megosztott kulcs (PSK):").grid(row=1, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame1, textvariable=self.vars['vpn_psk'], show="*").grid(row=1, column=1, sticky='ew')
        frame2 = ttk.LabelFrame(tab, text="II. Tunnel Interfész (VTI)", padding=10); frame2.pack(fill='x', expand=True, pady=5)
        ttk.Label(frame2, text="Tunnel ID:").grid(row=0, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['vpn_tunnel_id']).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame2, text="Tunnel IP cím/maszk:").grid(row=1, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['vpn_tunnel_ip'], width=40).grid(row=1, column=1, sticky='ew')
        ttk.Label(frame2, text="Tunnel Forrás (interfész):").grid(row=2, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame2, textvariable=self.vars['vpn_tunnel_source']).grid(row=2, column=1, sticky='ew')
        frame3 = ttk.LabelFrame(tab, text="III. Forgalomirányítás", padding=10); frame3.pack(fill='x', expand=True, pady=5)
        self.add_explanation(frame3, "Add meg a távoli hálózatot, hogy a router tudja, mit küldjön a VPN alagútba.", grid_pos=None)
        ttk.Label(frame3, text="Távoli Hálózat Címe:").grid(row=0, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame3, textvariable=self.vars['vpn_remote_net']).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame3, text="Távoli Hálózat Maszkja:").grid(row=1, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame3, textvariable=self.vars['vpn_remote_mask']).grid(row=1, column=1, sticky='ew')
        frame4 = ttk.LabelFrame(tab, text="IV. Haladó Titkosítási Beállítások (IKEv2 & IPsec)", padding=10); frame4.pack(fill='x', expand=True, pady=5)
        ttk.Label(frame4, text="IKEv2 Proposal:").grid(row=0, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame4, textvariable=self.vars['vpn_ike_proposal'], width=60).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame4, text="IPsec Transform Set:").grid(row=1, column=0, sticky='w', padx=5, pady=3); ttk.Entry(frame4, textvariable=self.vars['vpn_ipsec_transform'], width=60).grid(row=1, column=1, sticky='ew')

    def setup_management_tab(self, tab):
        frame1 = ttk.LabelFrame(tab, text="SNMP", padding=10); frame1.pack(fill='x', expand=True, pady=5)
        ttk.Checkbutton(frame1, text="SNMP Engedélyezése", variable=self.vars['snmp_enabled']).grid(row=0, columnspan=2, sticky='w')
        ttk.Label(frame1, text="Helyszín:").grid(row=1, column=0, sticky='w'); ttk.Entry(frame1, textvariable=self.vars['snmp_location'], width=40).grid(row=1, column=1, sticky='ew')
        ttk.Label(frame1, text="Kontakt:").grid(row=2, column=0, sticky='w'); ttk.Entry(frame1, textvariable=self.vars['snmp_contact'], width=40).grid(row=2, column=1, sticky='ew')
        ttk.Label(frame1, text="Community (RO):").grid(row=3, column=0, sticky='w'); ttk.Entry(frame1, textvariable=self.vars['snmp_community_ro']).grid(row=3, column=1, sticky='ew')
        frame2 = ttk.LabelFrame(tab, text="Naplózás (Syslog) és Időszinkronizáció (NTP)", padding=10); frame2.pack(fill='x', expand=True, pady=5)
        ttk.Label(frame2, text="Syslog Szerver IP:").grid(row=0, column=0, sticky='w'); ttk.Entry(frame2, textvariable=self.vars['syslog_host']).grid(row=0, column=1, sticky='ew')
        ttk.Label(frame2, text="NTP Szerverek (egy/sor):").grid(row=1, column=0, sticky='nw'); self.text_widgets['ntp_servers'] = tk.Text(frame2, height=3, width=30); self.text_widgets['ntp_servers'].grid(row=1, column=1, sticky='ew')

    def add_interface(self):
        dialog = InterfaceDialog(self); self.wait_window(dialog)
        if dialog.result: self.interfaces_data.append(dialog.result); self.update_interface_tree()

    def edit_interface(self):
        selected = self.iface_tree.selection();
        if not selected: messagebox.showwarning("Nincs kijelölés", "Kérlek, jelölj ki egy interfészt!"); return
        idx = self.iface_tree.index(selected[0]); current_data = self.interfaces_data[idx]
        dialog = InterfaceDialog(self, initial_data=current_data); self.wait_window(dialog)
        if dialog.result: self.interfaces_data[idx] = dialog.result; self.update_interface_tree()

    def remove_interface(self):
        selected = self.iface_tree.selection();
        if not selected: return
        if messagebox.askyesno("Törlés", "Biztosan törlöd a kijelölt interfészt?"):
            idx = self.iface_tree.index(selected[0]); del self.interfaces_data[idx]; self.update_interface_tree()
            
    def update_interface_tree(self):
        self.iface_tree.delete(*self.iface_tree.get_children())
        for item in self.interfaces_data:
            nat = []
            if item.get('nat_inside'): nat.append("Inside")
            if item.get('nat_outside'): nat.append("Outside")
            values = (item['name'], item['ip_mask'], item['desc'], "Up" if item['no_shut'] else "Down", ", ".join(nat))
            self.iface_tree.insert('', tk.END, values=values)

    def add_vlan(self):
        vlan_id = simpledialog.askstring("Új VLAN", "VLAN ID:");
        if not vlan_id or not vlan_id.isdigit(): return
        vlan_name = simpledialog.askstring("Új VLAN", f"VLAN {vlan_id} neve:");
        if not vlan_name: return
        self.vlans_data.append({'id': vlan_id, 'name': vlan_name}); self.update_vlan_tree()

    def remove_vlan(self):
        selected = self.vlan_tree.selection()
        if not selected: return
        idx = self.vlan_tree.index(selected[0]); del self.vlans_data[idx]; self.update_vlan_tree()

    def update_vlan_tree(self):
        self.vlan_tree.delete(*self.vlan_tree.get_children())
        for vlan in self.vlans_data: self.vlan_tree.insert('', tk.END, values=(vlan['id'], vlan['name']))

    def add_static_route(self):
        dialog = StaticRouteDialog(self); self.wait_window(dialog)
        if dialog.result: self.static_routes_data.append(dialog.result); self.update_static_route_tree()
            
    def remove_static_route(self):
        selected = self.static_tree.selection()
        if not selected: return
        idx = self.static_tree.index(selected[0]); del self.static_routes_data[idx]; self.update_static_route_tree()

    def update_static_route_tree(self):
        self.static_tree.delete(*self.static_tree.get_children())
        for route in self.static_routes_data: self.static_tree.insert('', tk.END, values=(route['dest'], route['mask'], route['next_hop']))
            
    def add_acl(self):
        dialog = AclDialog(self); self.wait_window(dialog)
        if dialog.result:
            name, type = dialog.result
            if not name: messagebox.showerror("Hiba", "Az ACL neve nem lehet üres!"); return
            if name in self.acls_data: messagebox.showerror("Hiba", "Ilyen nevű ACL már létezik!"); return
            self.acls_data[name] = {'type': type, 'rules': []}; self.update_acl_listbox()
            self.acl_listbox.select_set(self.acl_listbox.size() - 1); self.on_acl_select(None)
    
    def remove_acl(self):
        selected_idx = self.acl_listbox.curselection()
        if not selected_idx: return
        acl_name = self.acl_listbox.get(selected_idx[0])
        if messagebox.askyesno("Törlés", f"Biztosan törlöd a(z) '{acl_name}' ACL-t?"):
            del self.acls_data[acl_name]; self.update_acl_listbox(); self.acl_tree.delete(*self.acl_tree.get_children())
    
    def update_acl_listbox(self):
        self.acl_listbox.delete(0, tk.END);
        for name in self.acls_data: self.acl_listbox.insert(tk.END, name)

    def on_acl_select(self, event):
        selected_idx = self.acl_listbox.curselection();
        if not selected_idx: self.acl_tree.delete(*self.acl_tree.get_children()); return
        acl_name = self.acl_listbox.get(selected_idx[0]); self.acl_tree.delete(*self.acl_tree.get_children())
        if acl_name in self.acls_data:
            for i, rule in enumerate(self.acls_data[acl_name]['rules']):
                row = ((i + 1) * 10, rule.get('action', ''), rule.get('proto', ''), rule.get('src', ''), rule.get('dst', ''), rule.get('port', ''))
                self.acl_tree.insert('', tk.END, values=row)

    def add_acl_rule(self):
        selected_idx = self.acl_listbox.curselection()
        if not selected_idx: messagebox.showwarning("Nincs kijelölés", "Válassz ki egy ACL-t!"); return
        acl_name = self.acl_listbox.get(selected_idx[0]); acl_type = self.acls_data[acl_name]['type']
        dialog = AclRuleDialog(self, acl_type); self.wait_window(dialog)
        if dialog.result: self.acls_data[acl_name]['rules'].append(dialog.result); self.on_acl_select(None)

    def remove_acl_rule(self):
        sel_acl_idx = self.acl_listbox.curselection(); sel_rule = self.acl_tree.selection()
        if not sel_acl_idx or not sel_rule: return
        acl_name = self.acl_listbox.get(sel_acl_idx[0]); rule_idx = self.acl_tree.index(sel_rule[0])
        if messagebox.askyesno("Törlés", "Biztosan törlöd a kijelölt szabályt?"):
            del self.acls_data[acl_name]['rules'][rule_idx]; self.on_acl_select(None)

    def add_static_nat(self):
        dialog = StaticNatDialog(self); self.wait_window(dialog)
        if dialog.result: self.static_nat_data.append(dialog.result); self.update_static_nat_tree()

    def remove_static_nat(self):
        selected = self.static_nat_tree.selection();
        if not selected: return
        idx = self.static_nat_tree.index(selected[0]); del self.static_nat_data[idx]; self.update_static_nat_tree()
        
    def update_static_nat_tree(self):
        self.static_nat_tree.delete(*self.static_nat_tree.get_children())
        for item in self.static_nat_data: self.static_nat_tree.insert('', tk.END, values=(item['inside_ip'], item['outside_ip']))

    def add_port_fwd(self):
        dialog = PortFwdDialog(self); self.wait_window(dialog)
        if dialog.result: self.port_fwd_data.append(dialog.result); self.update_port_fwd_tree()
            
    def remove_port_fwd(self):
        selected = self.port_fwd_tree.selection();
        if not selected: return
        idx = self.port_fwd_tree.index(selected[0]); del self.port_fwd_data[idx]; self.update_port_fwd_tree()
        
    def update_port_fwd_tree(self):
        self.port_fwd_tree.delete(*self.port_fwd_tree.get_children())
        for item in self.port_fwd_data: self.port_fwd_tree.insert('', tk.END, values=(item['proto'], item['inside_ip'], item['inside_port'], item['outside_port']))

    def add_explanation(self, parent_frame, text, grid_pos):
        label = ttk.Label(parent_frame, text=f"ⓘ {text}", wraplength=450, justify=tk.LEFT, foreground='darkblue', font=('Arial', 9, 'italic'))
        if grid_pos: label.grid(row=grid_pos[0], column=grid_pos[1], columnspan=2, padx=5, pady=2, sticky='w')
        else: label.pack(fill='x', pady=5)
            
    def collect_data_for_jinja(self):
        data = {key: var.get() for key, var in self.vars.items()}
        data['current_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data.update({
            'interfaces': self.interfaces_data, 'vlans': self.vlans_data,
            'static_routes': self.static_routes_data, 'acls': self.acls_data,
            'static_nat_data': self.static_nat_data, 'port_fwd_data': self.port_fwd_data
        })
        for name, widget in self.text_widgets.items(): data[name] = widget.get("1.0", tk.END).strip()
        return data

    def generate_preview(self):
        data = self.collect_data_for_jinja()
        try:
            # MÓDOSÍTÁS: Nem fájlból, hanem a belső stringből töltjük be a sablont
            env = Environment(trim_blocks=True, lstrip_blocks=True)
            template = env.from_string(ROUTER_TEMPLATE_STRING)
            
            output_config = template.render(data)
            self.preview_text.delete('1.0', tk.END); self.preview_text.insert('1.0', output_config)
        except Exception as e:
            messagebox.showerror("Hiba a generálás során", f"Hiba történt a sablon feldolgozása közben:\n{e}")

    def generate_and_save(self):
        self.generate_preview(); output_config = self.preview_text.get('1.0', tk.END)
        if not output_config.strip(): messagebox.showwarning("Üres konfiguráció", "Nincs mit menteni."); return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"{self.vars['hostname'].get()}_config.txt",
            title="Konfiguráció mentése", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f: f.write(output_config)
            messagebox.showinfo("Siker", f"Konfiguráció sikeresen elmentve:\n{filepath}")

# --- FELUGRÓ ABLAKOK (DIALOGS) ---

class BaseDialog(Toplevel):
    def __init__(self, parent, title):
        super().__init__(parent); self.transient(parent); self.title(title); self.result = None
        self.body = ttk.Frame(self, padding=15); self.body.pack(fill='both', expand=True)
        self.create_widgets(); self.create_buttons()
        self.grab_set(); self.protocol("WM_DELETE_WINDOW", self.cancel); self.wait_window(self)
    def create_widgets(self): pass
    def create_buttons(self):
        btn_frame = ttk.Frame(self); btn_frame.pack(pady=(0, 10), padx=10, fill='x')
        ttk.Button(btn_frame, text="OK", command=self.ok, style='Accent.TButton').pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Mégse", command=self.cancel).pack(side=tk.RIGHT, padx=5)
    def ok(self): self.destroy()
    def cancel(self): self.destroy()

class InterfaceDialog(BaseDialog):
    def __init__(self, parent, initial_data=None): self.initial_data = initial_data or {}; super().__init__(parent, "Interfész Beállítások")
    def create_widgets(self):
        ttk.Label(self.body, text="Típus:").grid(row=0, column=0, sticky='w', pady=3)
        self.type_var = tk.StringVar(value=self.initial_data.get('type', 'Fizikai')); ttk.Combobox(self.body, textvariable=self.type_var, values=['Fizikai', 'VLAN', 'Loopback']).grid(row=0, column=1, sticky='ew')
        ttk.Label(self.body, text="Név/Szám:").grid(row=1, column=0, sticky='w', pady=3); self.name_var = tk.StringVar(value=self.initial_data.get('raw_name', 'GigabitEthernet0/0')); ttk.Entry(self.body, textvariable=self.name_var).grid(row=1, column=1, sticky='ew')
        ttk.Label(self.body, text="IP Cím/Maszk:").grid(row=2, column=0, sticky='w', pady=3); self.ip_mask_var = tk.StringVar(value=self.initial_data.get('ip_mask', '192.168.1.1 255.255.255.0')); ttk.Entry(self.body, textvariable=self.ip_mask_var, width=40).grid(row=2, column=1, sticky='ew')
        ttk.Label(self.body, text="Leírás:").grid(row=3, column=0, sticky='w', pady=3); self.desc_var = tk.StringVar(value=self.initial_data.get('desc', '')); ttk.Entry(self.body, textvariable=self.desc_var, width=40).grid(row=3, column=1, sticky='ew')
        self.no_shut_var = tk.BooleanVar(value=self.initial_data.get('no_shut', True)); ttk.Checkbutton(self.body, text="Engedélyezés (no shutdown)", variable=self.no_shut_var).grid(row=4, columnspan=2, sticky='w', pady=2)
        self.nat_inside_var = tk.BooleanVar(value=self.initial_data.get('nat_inside', False)); ttk.Checkbutton(self.body, text="NAT Belső Interfész (ip nat inside)", variable=self.nat_inside_var).grid(row=5, columnspan=2, sticky='w', pady=2)
        self.nat_outside_var = tk.BooleanVar(value=self.initial_data.get('nat_outside', False)); ttk.Checkbutton(self.body, text="NAT Külső Interfész (ip nat outside)", variable=self.nat_outside_var).grid(row=6, columnspan=2, sticky='w', pady=2)
    def ok(self):
        raw_name = self.name_var.get(); iface_type = self.type_var.get()
        full_name = {"Fizikai": raw_name, "VLAN": f"Vlan{raw_name}", "Loopback": f"Loopback{raw_name}"}.get(iface_type, raw_name)
        self.result = {'type': iface_type, 'raw_name': raw_name, 'name': full_name, 'ip_mask': self.ip_mask_var.get(), 'desc': self.desc_var.get(), 'no_shut': self.no_shut_var.get(), 'nat_inside': self.nat_inside_var.get(), 'nat_outside': self.nat_outside_var.get()}; super().ok()

class StaticRouteDialog(BaseDialog):
    def __init__(self, parent): super().__init__(parent, "Statikus Útvonal")
    def create_widgets(self):
        ttk.Label(self.body, text="Célhálózat:").grid(row=0, column=0, sticky='w'); self.dest_var = tk.StringVar(value="0.0.0.0"); ttk.Entry(self.body, textvariable=self.dest_var).grid(row=0, column=1)
        ttk.Label(self.body, text="Maszk:").grid(row=1, column=0, sticky='w'); self.mask_var = tk.StringVar(value="0.0.0.0"); ttk.Entry(self.body, textvariable=self.mask_var).grid(row=1, column=1)
        ttk.Label(self.body, text="Next-Hop / Interfész:").grid(row=2, column=0, sticky='w'); self.next_hop_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.next_hop_var, width=30).grid(row=2, column=1)
    def ok(self): self.result = {'dest': self.dest_var.get(), 'mask': self.mask_var.get(), 'next_hop': self.next_hop_var.get()}; super().ok()

class AclDialog(BaseDialog):
    def __init__(self, parent): super().__init__(parent, "Új Access-List")
    def create_widgets(self):
        ttk.Label(self.body, text="Azonosító (szám/név):").grid(row=0, column=0, sticky='w'); self.name_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.name_var).grid(row=0, column=1)
        ttk.Label(self.body, text="Típus:").grid(row=1, column=0, sticky='w'); self.type_var = tk.StringVar(value="standard"); ttk.Combobox(self.body, textvariable=self.type_var, values=["standard", "extended"]).grid(row=1, column=1)
    def ok(self): self.result = (self.name_var.get(), self.type_var.get()); super().ok()

class AclRuleDialog(BaseDialog):
    def __init__(self, parent, acl_type="standard"): self.acl_type = acl_type; super().__init__(parent, "Új ACL Szabály")
    def create_widgets(self):
        ttk.Label(self.body, text="Művelet:").grid(row=0, column=0, sticky='w'); self.action_var = tk.StringVar(value="permit"); ttk.Combobox(self.body, textvariable=self.action_var, values=["permit", "deny"]).grid(row=0, column=1)
        ttk.Label(self.body, text="Forrás (IP/wildcard):").grid(row=1, column=0, sticky='w'); self.src_var = tk.StringVar(value="any"); ttk.Entry(self.body, textvariable=self.src_var).grid(row=1, column=1)
        if self.acl_type == "extended":
            ttk.Label(self.body, text="Protokoll:").grid(row=2, column=0, sticky='w'); self.proto_var = tk.StringVar(value="ip"); ttk.Combobox(self.body, textvariable=self.proto_var, values=["ip", "tcp", "udp", "icmp"]).grid(row=2, column=1)
            ttk.Label(self.body, text="Cél (IP/wildcard):").grid(row=3, column=0, sticky='w'); self.dst_var = tk.StringVar(value="any"); ttk.Entry(self.body, textvariable=self.dst_var).grid(row=3, column=1)
            ttk.Label(self.body, text="Port (pl. eq 80):").grid(row=4, column=0, sticky='w'); self.port_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.port_var).grid(row=4, column=1)
    def ok(self):
        self.result = {'action': self.action_var.get(), 'src': self.src_var.get()}
        if self.acl_type == "extended": self.result.update({'proto': self.proto_var.get(), 'dst': self.dst_var.get(), 'port': self.port_var.get()})
        super().ok()

class StaticNatDialog(BaseDialog):
    def __init__(self, parent): super().__init__(parent, "Új Statikus 1:1 NAT")
    def create_widgets(self):
        ttk.Label(self.body, text="Belső Lokális IP:").grid(row=0, column=0, sticky='w', pady=5); self.inside_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.inside_var).grid(row=0, column=1)
        ttk.Label(self.body, text="Külső Globális IP:").grid(row=1, column=0, sticky='w', pady=5); self.outside_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.outside_var).grid(row=1, column=1)
    def ok(self): self.result = {'inside_ip': self.inside_var.get(), 'outside_ip': self.outside_var.get()}; super().ok()

class PortFwdDialog(BaseDialog):
    def __init__(self, parent): super().__init__(parent, "Új Port Forwarding Szabály")
    def create_widgets(self):
        ttk.Label(self.body, text="Protokoll:").grid(row=0, column=0, sticky='w', pady=5); self.proto_var = tk.StringVar(value="tcp"); ttk.Combobox(self.body, textvariable=self.proto_var, values=["tcp", "udp"]).grid(row=0, column=1)
        ttk.Label(self.body, text="Belső IP Cím:").grid(row=1, column=0, sticky='w', pady=5); self.inside_ip_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.inside_ip_var).grid(row=1, column=1)
        ttk.Label(self.body, text="Belső Port:").grid(row=2, column=0, sticky='w', pady=5); self.inside_port_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.inside_port_var).grid(row=2, column=1)
        ttk.Label(self.body, text="Külső Port:").grid(row=3, column=0, sticky='w', pady=5); self.outside_port_var = tk.StringVar(); ttk.Entry(self.body, textvariable=self.outside_port_var).grid(row=3, column=1)
    def ok(self): self.result = {'proto': self.proto_var.get(), 'inside_ip': self.inside_ip_var.get(), 'inside_port': self.inside_port_var.get(), 'outside_port': self.outside_port_var.get()}; super().ok()


if __name__ == "__main__":
    app = CiscoConfigApp()
    app.mainloop()
