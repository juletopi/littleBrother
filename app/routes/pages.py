from flask import Blueprint, render_template

pages_bp = Blueprint("pages", __name__)


@pages_bp.get("/")
def home():
	return render_template("menu.html")


@pages_bp.get("/scanner")
def scanner_page():
	return render_template("scanner.html")


@pages_bp.get("/zip-cracker")
def zip_cracker_page():
	return render_template("zip_cracker.html")
