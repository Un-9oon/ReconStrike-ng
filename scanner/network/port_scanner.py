"""High-speed asynchronous TCP port scanner for internal network auditing.

Supports scanning individual hosts, CIDR ranges, and port ranges from
top-1000 to full 65535.  Uses asyncio for high concurrency without
requiring raw sockets or root privileges.

Usage from CLI::

    reconstrike --network-scan 192.168.1.0/24 --ports top-1000
    reconstrike --network-scan 10.0.0.1 --ports 1-65535 --scan-speed 5
"""

import asyncio
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from scanner.log import logger


# ---------------------------------------------------------------------------
# Top-1000 TCP ports (Nmap default) — the most commonly open ports
# ---------------------------------------------------------------------------
TOP_1000_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
    37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
    100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
    163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
    311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
    464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
    548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
    667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
    777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
    903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002,
    1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028,
    1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052,
    1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
    1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076,
    1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088,
    1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100,
    1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117,
    1119, 1121, 1122, 1131, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152,
    1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187,
    1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
    1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310,
    1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494,
    1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641,
    1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755,
    1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
    1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001,
    2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021,
    2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046,
    2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111,
    2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
    2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393,
    2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
    2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811,
    2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005,
    3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168,
    3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404,
    3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737,
    3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
    3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129,
    4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567,
    4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030,
    5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120,
    5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405,
    5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631,
    5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815,
    5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906,
    5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962,
    5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005,
    6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156,
    6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666,
    6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881,
    6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103,
    7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741,
    7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002,
    8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100,
    8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300,
    8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701,
    8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011,
    9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103,
    9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503,
    9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
    9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003,
    10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243,
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000,
    14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000,
    16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988,
    18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842,
    20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444,
    24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715,
    28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771,
    32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781,
    32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500,
    38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
    49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001,
    50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
    52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
    56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078,
    63331, 64623, 64680, 65000, 65129, 65389,
]

# Well-known service names for common ports
SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos",
    465: "SMTPS", 500: "IKE", 514: "Syslog", 515: "LPD",
    520: "RIP", 523: "IBM-DB2", 524: "NCP", 541: "FortiGate",
    548: "AFP", 554: "RTSP", 563: "NNTPS", 587: "SMTP-Submission",
    593: "HTTP-RPC", 631: "IPP/CUPS", 636: "LDAPS", 873: "Rsync",
    902: "VMware", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1099: "RMI", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL-UDP",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 1900: "UPnP",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL", 2181: "ZooKeeper",
    2375: "Docker-API", 2376: "Docker-API-TLS", 2377: "Docker-Swarm",
    3000: "Grafana/Node", 3268: "LDAP-GC", 3269: "LDAP-GC-SSL",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4443: "HTTPS-Alt",
    4444: "Metasploit", 5000: "UPnP/Flask", 5432: "PostgreSQL",
    5555: "ADB", 5601: "Kibana", 5672: "AMQP/RabbitMQ",
    5900: "VNC", 5984: "CouchDB", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "Kubernetes-API", 6666: "IRC",
    6667: "IRC", 7001: "WebLogic", 7070: "RealServer",
    7443: "Oracle-HTTPS", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8009: "AJP", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8443: "HTTPS-Alt", 8500: "Consul", 8834: "Nessus",
    8888: "HTTP-Alt", 9000: "SonarQube", 9042: "Cassandra",
    9090: "Prometheus", 9092: "Kafka", 9100: "Printer",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    9418: "Git", 9999: "Urchin", 10000: "Webmin",
    10250: "Kubelet", 10255: "Kubelet-RO", 11211: "Memcached",
    11214: "Memcached-SSL", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-HTTP",
    50000: "SAP", 50070: "HDFS-NameNode", 61616: "ActiveMQ",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class PortResult:
    """Result of scanning a single port on a host."""
    host: str
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""

    @property
    def is_open(self) -> bool:
        return self.state == "open"


@dataclass
class HostResult:
    """Aggregated scan results for a single host."""
    ip: str
    hostname: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    os_guess: str = ""
    scan_time: float = 0.0

    @property
    def is_alive(self) -> bool:
        return len(self.open_ports) > 0


# ---------------------------------------------------------------------------
# Scan speed profiles
# ---------------------------------------------------------------------------
SPEED_PROFILES = {
    1: {"concurrency": 50, "timeout": 3.0, "delay": 0.1, "label": "Stealth"},
    2: {"concurrency": 150, "timeout": 2.5, "delay": 0.05, "label": "Polite"},
    3: {"concurrency": 300, "timeout": 2.0, "delay": 0.01, "label": "Normal"},
    4: {"concurrency": 500, "timeout": 1.5, "delay": 0.0, "label": "Aggressive"},
    5: {"concurrency": 1000, "timeout": 1.0, "delay": 0.0, "label": "Insane"},
}


# ---------------------------------------------------------------------------
# Core async scanner
# ---------------------------------------------------------------------------
async def _scan_port_async(host: str, port: int, timeout: float,
                           semaphore: asyncio.Semaphore) -> PortResult:
    """Scan a single port using async TCP connect."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()

            service = SERVICE_NAMES.get(port, "")
            return PortResult(host=host, port=port, state="open", service=service)

        except asyncio.TimeoutError:
            return PortResult(host=host, port=port, state="filtered")
        except (ConnectionRefusedError, ConnectionResetError):
            return PortResult(host=host, port=port, state="closed")
        except OSError:
            return PortResult(host=host, port=port, state="filtered")


async def _scan_host_async(host: str, ports: list[int],
                           speed: int = 3) -> HostResult:
    """Scan all specified ports on a single host."""
    profile = SPEED_PROFILES.get(speed, SPEED_PROFILES[3])
    semaphore = asyncio.Semaphore(profile["concurrency"])
    timeout = profile["timeout"]

    start = time.time()

    tasks = [_scan_port_async(host, port, timeout, semaphore) for port in ports]
    results = await asyncio.gather(*tasks)

    elapsed = time.time() - start

    # Resolve hostname
    hostname = ""
    try:
        hostname = socket.getfqdn(host)
        if hostname == host:
            hostname = ""
    except Exception:
        pass

    open_ports = [r for r in results if r.is_open]
    open_ports.sort(key=lambda r: r.port)

    return HostResult(
        ip=host,
        hostname=hostname,
        open_ports=open_ports,
        scan_time=elapsed,
    )


def scan_host(host: str, ports: list[int] | None = None,
              speed: int = 3) -> HostResult:
    """Synchronous wrapper: scan a single host.

    Args:
        host:  IP address or hostname to scan.
        ports: List of ports to scan. Defaults to top-1000.
        speed: Scan speed 1-5 (1=stealth, 5=insane).

    Returns:
        HostResult with all open ports found.
    """
    if ports is None:
        ports = TOP_1000_PORTS

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        logger.error("Network: Cannot resolve host: %s", host)
        return HostResult(ip=host)

    return asyncio.run(_scan_host_async(ip, ports, speed))


def scan_network(cidr: str, ports: list[int] | None = None,
                 speed: int = 3) -> list[HostResult]:
    """Scan an entire CIDR range.

    Args:
        cidr:  CIDR notation (e.g., "192.168.1.0/24").
        ports: List of ports to scan per host. Defaults to top-1000.
        speed: Scan speed 1-5.

    Returns:
        List of HostResult for all hosts with at least one open port.
    """
    if ports is None:
        ports = TOP_1000_PORTS

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        logger.error("Network: Invalid CIDR: %s — %s", cidr, e)
        return []

    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        # Single host (e.g., /32)
        hosts = [str(network.network_address)]

    logger.info("Network: Scanning %d hosts in %s (speed=%d, ports=%d)",
                len(hosts), cidr, speed, len(ports))

    results = []

    async def _scan_all():
        tasks = [_scan_host_async(h, ports, speed) for h in hosts]
        return await asyncio.gather(*tasks)

    all_results = asyncio.run(_scan_all())

    # Filter to only alive hosts
    alive = [r for r in all_results if r.is_alive]
    alive.sort(key=lambda r: ipaddress.ip_address(r.ip))

    return alive


def parse_port_range(port_str: str) -> list[int]:
    """Parse a port specification string into a list of port numbers.

    Supports:
        "top-1000"   -> Nmap top-1000 ports
        "1-1024"     -> Range
        "22,80,443"  -> Comma-separated
        "1-65535"    -> Full scan
        "80,443,8000-9000"  -> Mixed
    """
    port_str = port_str.strip().lower()

    if port_str in ("top-1000", "top1000", "default"):
        return TOP_1000_PORTS
    if port_str in ("all", "full", "1-65535"):
        return list(range(1, 65536))

    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass

    return sorted(ports)
