import os
import threading
import uuid
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from app.services.zip_cracker import ZipCracker

zip_cracker_bp = Blueprint("zip_cracker", __name__)
cracking_sessions = {}
sessions_lock = threading.Lock()


def _session_response(session_id, session):
	finished_at = session["finished_at"]
	elapsed_seconds = (finished_at or datetime.now(timezone.utc)).timestamp() - session["started_at"].timestamp()
	response = {
		"session_id": session_id,
		"status": session["status"],
		"progresso": session["progresso"],
		"total": session["total"],
		"logs": session["logs"][-50:],
		"elapsed_seconds": round(max(elapsed_seconds, 0), 2),
	}
	if session["resultado"]:
		response["resultado"] = session["resultado"]
	if session["erro"]:
		response["erro"] = session["erro"]
	return response


def _append_log(session, message, level="info"):
	session["logs"].append({"message": message, "level": level, "at": datetime.now(timezone.utc).isoformat()})


def _execute_crack(session_id, cracker, zip_path, wordlist_path):
	try:
		with sessions_lock:
			session = cracking_sessions[session_id]
			session["status"] = "processando"
			session["started_at"] = datetime.now(timezone.utc)
			_append_log(session, "Operação iniciada.")
		with open(wordlist_path, "r", errors="ignore") as wordlist:
			session["total"] = sum(1 for line in wordlist if line.strip())

		for progress in cracker.crack_password(
			cancel_check=lambda: cracking_sessions[session_id]["cancel_requested"]
		):
			with sessions_lock:
				session = cracking_sessions[session_id]
				if progress.get("current_password") is not None:
					session["progresso"] = progress["current_password"]
				if progress.get("current_text"):
					session["last_password"] = progress["current_text"]
				if progress.get("info"):
					_append_log(session, progress["info"])
				if progress.get("warning"):
					_append_log(session, progress["warning"], "warning")
				if progress.get("password"):
					session["status"] = "sucesso"
					session["progresso"] = session["total"]
					session["resultado"] = {
						"senha": progress["password"],
						"metodo": progress.get("method", "zipfile"),
						"tentativas": progress.get("current_password", 0),
					}
					_append_log(session, "Senha encontrada.", "success")
				if progress.get("error"):
					session["status"] = "cancelado" if session["cancel_requested"] else "erro"
					session["erro"] = progress["error"]
					_append_log(session, progress["error"], "error")
				if session["cancel_requested"]:
					session["status"] = "cancelado"
					_append_log(session, "Operação cancelada.", "warning")
					break
		with sessions_lock:
			if cracking_sessions[session_id]["status"] == "processando":
				cracking_sessions[session_id]["status"] = "concluido"
			cracking_sessions[session_id]["finished_at"] = datetime.now(timezone.utc)
	except Exception as exc:
		with sessions_lock:
			session = cracking_sessions.get(session_id)
			if session:
				session["status"] = "erro"
				session["erro"] = str(exc)
				_append_log(session, str(exc), "error")
				session["finished_at"] = datetime.now(timezone.utc)
	finally:
		with sessions_lock:
			session = cracking_sessions.get(session_id)
			if session and session["finished_at"] is None:
				session["finished_at"] = datetime.now(timezone.utc)
		for path in (zip_path, wordlist_path):
			try:
				os.remove(path)
			except OSError:
				pass


@zip_cracker_bp.post("/api/crack")
def start_crack():
	zip_file = request.files.get("zip_file")
	wordlist_file = request.files.get("wordlist")
	if not zip_file or not wordlist_file or not zip_file.filename or not wordlist_file.filename:
		return jsonify({"error": "Envie um arquivo ZIP e uma wordlist."}), 400
	if not zip_file.filename.lower().endswith(".zip"):
		return jsonify({"error": "Apenas arquivos .zip são permitidos."}), 400

	session_id = uuid.uuid4().hex
	upload_folder = current_app.config["ZIP_UPLOAD_FOLDER"]
	os.makedirs(upload_folder, exist_ok=True)
	zip_path = os.path.join(upload_folder, f"{session_id}_{secure_filename(zip_file.filename)}")
	wordlist_path = os.path.join(upload_folder, f"{session_id}_{secure_filename(wordlist_file.filename)}")
	try:
		zip_file.save(zip_path)
		wordlist_file.save(wordlist_path)
		cracker = ZipCracker(zip_path, wordlist_path)
		with sessions_lock:
			cracking_sessions[session_id] = {
				"status": "iniciado",
				"progresso": 0,
				"total": 0,
				"resultado": None,
				"erro": None,
				"logs": [],
				"last_password": "",
				"cancel_requested": False,
				"started_at": datetime.now(timezone.utc),
				"finished_at": None,
			}
		thread = threading.Thread(target=_execute_crack, args=(session_id, cracker, zip_path, wordlist_path), daemon=True)
		thread.start()
		return jsonify({"success": True, "session_id": session_id}), 202
	except Exception as exc:
		for path in (zip_path, wordlist_path):
			try:
				os.remove(path)
			except OSError:
				pass
		return jsonify({"error": str(exc)}), 500


@zip_cracker_bp.get("/api/progress/<session_id>")
def crack_progress(session_id):
	with sessions_lock:
		session = cracking_sessions.get(session_id)
		if not session:
			return jsonify({"error": "Sessão não encontrada."}), 404
		return jsonify(_session_response(session_id, session))


@zip_cracker_bp.post("/api/crack/<session_id>/cancel")
def cancel_crack(session_id):
	with sessions_lock:
		session = cracking_sessions.get(session_id)
		if not session:
			return jsonify({"error": "Sessão não encontrada."}), 404
		session["cancel_requested"] = True
		_append_log(session, "Cancelamento solicitado.", "warning")
		return jsonify({"success": True})
