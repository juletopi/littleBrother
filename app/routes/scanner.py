import time

from flask import Blueprint, jsonify, request

from app.services.network_scanner import (
	build_environment_info,
	build_environment_warnings,
	parse_ports,
	parse_protocols,
	parse_targets,
	run_scan,
	summarize,
)

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.get("/api/info")
def api_info():
	return jsonify({"ok": True, "environment": build_environment_info()})


@scanner_bp.post("/api/scan")
def api_scan():
	payload = request.get_json(silent=True) or {}
	try:
		targets = parse_targets(payload.get("targets", []))
		ports = parse_ports(payload.get("ports", "1-1024"))
		protocols = parse_protocols(payload.get("protocols", "tcp,udp"))
		timeout = float(payload.get("timeout", 1.0))
		workers = int(payload.get("workers", 200))
		tcp_method = str(payload.get("tcp_method", "connect")).lower()
		prefer_syn = tcp_method == "syn"
	except ValueError as exc:
		return jsonify({"ok": False, "error": str(exc)}), 400
	except Exception as exc:
		return jsonify({"ok": False, "error": f"Erro na entrada: {exc}"}), 400

	timeout = min(max(timeout, 0.05), 10.0)
	workers = min(max(workers, 1), 1000)
	started_at = time.time()
	results, syn_used = run_scan(targets, ports, protocols, timeout, workers, prefer_syn)
	duration = round(time.time() - started_at, 3)
	return jsonify({
		"ok": True,
		"scan": {
			"targets": targets,
			"ports": ports,
			"protocols": protocols,
			"timeout": timeout,
			"workers": workers,
			"tcp_method": "syn" if syn_used else "connect",
			"duration_seconds": duration,
		},
		"summary": summarize(results),
		"results": results,
		"warnings": build_environment_warnings(tcp_method, syn_used),
	})
