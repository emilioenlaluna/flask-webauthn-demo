# webauthn_demo/auth.py
from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, session, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, login_user, logout_user
from .app import db
from .models import User

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = db.session.scalar(User.select().where(User.username == username))
        if not user or not check_password_hash(user.password_hash, password):
            flash("Usuario o contraseña incorrectos.")
            return redirect(url_for("auth.login"))

        if user.keys:
            session["user_id"] = user.id
            return redirect(url_for("webauthn.login"))

        login_user(user)
        return redirect(url_for("main.index"))
    return render_template("login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if db.session.scalar(User.select().where(User.username == username)):
            flash("Ese nombre de usuario ya existe.")
            return redirect(url_for("auth.register"))

        user = User(username=username,
                    password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        flash("Usuario creado correctamente. Ya puedes iniciar sesión.")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión.")
    return redirect(url_for("main.index"))
