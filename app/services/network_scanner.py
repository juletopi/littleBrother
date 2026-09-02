import errno
import os
import platform
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address

try:
	from scapy.all import IP, TCP, conf, sr1

	SCAPY_AVAILABLE = True
except Exception:
	SCAPY_AVAILABLE = False


def build_environment_info():
	current_platform = platform.system().lower()
	is_linux = current_platform == "linux"
	is_windows = current_platform == "windows"
	return {
		"platform": current_platform,
		"platform_name": platform.system(),
		"is_linux": is_linux,
		"is_windows": is_windows,
		"scapy_available": SCAPY_AVAILABLE,
		"syn_scan_available": is_linux and SCAPY_AVAILABLE,
		"notes": [
			"O modo SYN funciona de forma mais previsivel em Linux com privilegios elevados.",
			"No Windows, o backend tende a usar TCP connect scan como fallback.",
			"Se a maquina alvo estiver protegida por firewall, portas podem aparecer como filtered.",
		],
	}


def build_environment_warnings(requested_method, syn_used):
	warnings = []
	environment = build_environment_info()
	if environment["is_windows"]:
		warnings.append("Voce esta em Windows: resultados de scan costumam sofrer mais com firewall, permissões e bloqueios de rede.")
	if requested_method == "syn" and not syn_used:
		warnings.append("SYN scan nao disponivel neste ambiente. O backend usou TCP connect scan como fallback.")
	if not environment["scapy_available"] and requested_method == "syn":
		warnings.append("Scapy nao foi detectado neste ambiente, entao o modo SYN nao pode ser executado.")
	return warnings


def parse_targets(raw_targets):
	if isinstance(raw_targets, str):
		targets = [item.strip() for item in raw_targets.replace(";", ",").split(",") if item.strip()]
	elif isinstance(raw_targets, list):
		targets = [str(item).strip() for item in raw_targets if str(item).strip()]
	else:
		raise ValueError("Campo 'targets' deve ser string ou lista de IPs.")
	if not targets:
		raise ValueError("Informe ao menos um IP em 'targets'.")
	validated = []
	for target in targets:
		try:
			validated.append(str(ip_address(target)))
		except ValueError as exc:
			raise ValueError(f"IP invalido: {target}") from exc
	return validated


def parse_ports(raw_ports):
	if isinstance(raw_ports, int):
		raw_ports = str(raw_ports)
	if not isinstance(raw_ports, str) or not raw_ports.strip():
		raise ValueError("Campo 'ports' deve ser uma string (ex.: '22,80,443,1-1024').")
	ports = set()
	for chunk in [part.strip() for part in raw_ports.split(",") if part.strip()]:
		if "-" in chunk:
			start_str, end_str = chunk.split("-", 1)
			if not start_str.isdigit() or not end_str.isdigit():
				raise ValueError(f"Faixa de portas invalida: '{chunk}'. Use formato como 20-80.")
			start_port, end_port = int(start_str), int(end_str)
			if start_port > end_port:
				start_port, end_port = end_port, start_port
			for port in range(start_port, end_port + 1):
				if 1 <= port <= 65535:
					ports.add(port)
		else:
			if not chunk.isdigit():
				raise ValueError(f"Porta invalida: '{chunk}'. Use numeros, listas por virgula ou faixas (ex.: 22,80,443,1-1024).")
			port = int(chunk)
			if 1 <= port <= 65535:
				ports.add(port)
	if not ports:
		raise ValueError("Nenhuma porta valida encontrada em 'ports'.")
	return sorted(ports)


def parse_protocols(raw_protocols):
	if raw_protocols is None:
		return ["tcp", "udp"]
	if isinstance(raw_protocols, str):
		protocols = [item.strip().lower() for item in raw_protocols.split(",") if item.strip()]
	elif isinstance(raw_protocols, list):
		protocols = [str(item).strip().lower() for item in raw_protocols if str(item).strip()]
	else:
		raise ValueError("Campo 'protocols' deve ser string ou lista.")
	invalid = [proto for proto in protocols if proto not in {"tcp", "udp"}]
	if invalid:
		raise ValueError(f"Protocolos invalidos: {', '.join(invalid)}")
	if not protocols:
		raise ValueError("Informe ao menos um protocolo (tcp, udp).")
	return sorted(set(protocols))


def can_use_syn_scan():
	if platform.system().lower() != "linux" or not SCAPY_AVAILABLE:
		return False
	try:
		return os.geteuid() == 0
	except AttributeError:
		return False


def tcp_connect_scan(target, port, timeout):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(timeout)
	try:
		code = sock.connect_ex((target, port))
		if code == 0:
			return "open"
		if code in {errno.ECONNREFUSED, 111, 10061}:
			return "closed"
		if code in {errno.ETIMEDOUT, 110, 10060}:
			return "filtered"
		return "filtered"
	except socket.timeout:
		return "filtered"
	except OSError:
		return "filtered"
	finally:
		sock.close()


def tcp_syn_scan(target, port, timeout):
	conf.verb = 0
	packet = IP(dst=target) / TCP(dport=port, flags="S")
	response = sr1(packet, timeout=timeout, verbose=False)
	if response is None:
		return "filtered"
	if response.haslayer(TCP):
		flags = response.getlayer(TCP).flags
		if flags & 0x12:
			return "open"
		if flags & 0x14:
			return "closed"
	return "filtered"


def udp_probe_scan(target, port, timeout):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	try:
		sock.connect((target, port))
		sock.send(b"\x00")
		data = sock.recv(1024)
		return "open" if data is not None else "filtered"
	except socket.timeout:
		return "filtered"
	except ConnectionRefusedError:
		return "closed"
	except OSError as exc:
		return "closed" if exc.errno in {errno.ECONNREFUSED, 111, 10061} else "filtered"
	finally:
		sock.close()


def run_scan(targets, ports, protocols, timeout, workers, prefer_syn):
	results = {target: {"tcp": [], "udp": []} for target in targets}
	use_syn = prefer_syn and can_use_syn_scan()

	def worker(target, port, protocol):
		if protocol == "tcp":
			status = tcp_syn_scan(target, port, timeout) if use_syn else tcp_connect_scan(target, port, timeout)
		else:
			status = udp_probe_scan(target, port, timeout)
		return target, protocol, port, status

	jobs = [(target, port, protocol) for target in targets for port in ports for protocol in protocols]
	with ThreadPoolExecutor(max_workers=workers) as executor:
		futures = [executor.submit(worker, target, port, protocol) for target, port, protocol in jobs]
		for future in as_completed(futures):
			target, protocol, port, status = future.result()
			results[target][protocol].append({"port": port, "status": status})
	for target in targets:
		for protocol in protocols:
			results[target][protocol].sort(key=lambda item: item["port"])
	return results, use_syn


def summarize(results):
	summary = {"tcp": {"open": 0, "closed": 0, "filtered": 0}, "udp": {"open": 0, "closed": 0, "filtered": 0}}
	for target_result in results.values():
		for protocol in ["tcp", "udp"]:
			for item in target_result[protocol]:
				summary[protocol][item["status"]] += 1
	return summary
