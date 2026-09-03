import os

from flask import Flask


def create_app():
	app = Flask(__name__, static_folder="..", static_url_path="", template_folder="../templates")
	app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
	app.config["ZIP_UPLOAD_FOLDER"] = os.path.join(app.root_path, "..", "uploads", "zip")

	from app.routes.pages import pages_bp
	from app.routes.scanner import scanner_bp
	from app.routes.zip_cracker import zip_cracker_bp

	app.register_blueprint(pages_bp)
	app.register_blueprint(scanner_bp)
	app.register_blueprint(zip_cracker_bp)
	return app
