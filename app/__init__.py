from flask import Flask


def create_app():
	app = Flask(__name__, static_folder="..", static_url_path="", template_folder="../templates")

	from app.routes.pages import pages_bp
	from app.routes.scanner import scanner_bp

	app.register_blueprint(pages_bp)
	app.register_blueprint(scanner_bp)
	return app
