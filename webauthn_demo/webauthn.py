import logging, time, traceback

from flask import (
    Blueprint, render_template, redirect, url_for,
    request, flash, session, current_app
)
from flask_login import login_required, login_user, current_user

from webauthn import (
    generate_registration_options, options_to_json, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, ResidentKeyRequirement, RegistrationCredential,
    UserVerificationRequirement, PublicKeyCredentialDescriptor, AuthenticationCredential,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers import exceptions as wex      # <── NUEVO

from .app import db
from .models import load_user, Key


bp = Blueprint("webauthn", __name__)


# ────────────────────────────────────────────────────────────────
#  Utilidades
# ────────────────────────────────────────────────────────────────
def _log_exc(msg: str) -> None:
    """
    Registra en ERROR la excepción actual con traceback completo.
    """
    current_app.logger.error("%s\n%s", msg, traceback.format_exc())


def _rp_cfg() -> tuple[str, str]:
    """Devuelve (rp_id, origin) desde la configuración global."""
    cfg = current_app.config
    return cfg["WEBAUTHN_RP_ID"], cfg["WEBAUTHN_RP_ORIGIN"]


# ────────────────────────────────────────────────────────────────
#  Vistas
# ────────────────────────────────────────────────────────────────
@bp.route("/keys", methods=["GET"])
@login_required
def keys() -> str:
    return render_template("security_keys.html")


@bp.route("/webauthn/register", methods=["GET", "POST"])
@login_required
def register():
    rp_id, origin = _rp_cfg()

    if request.method == "GET":
        options = generate_registration_options(
            user_id=str(current_user.id),
            user_name=current_user.username,
            rp_id=rp_id,
            rp_name=current_app.config["WEBAUTHN_RP_NAME"],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(k.credential_id))
                for k in current_user.keys
            ],
        )
        session["challenge"] = options.challenge

        return render_template(
            "webauthn_register.html",
            options=options_to_json(options),
            key_name=f"Security key #{len(current_user.keys) + 1}",
        )

    # POST  ─────────────────────────────────────────────────────┐
    try:
        credential = RegistrationCredential.parse_raw(request.form["credential"])
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=session.pop("challenge"),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=False,
        )

    except wex.InvalidRegistrationResponse as e:
        current_app.logger.warning("Registro WebAuthn inválido: %s", e)
        flash(f"Registro inválido: {e}")
        return redirect(url_for("webauthn.register"))

    except Exception:
        _log_exc("Excepción inesperada en registro WebAuthn")
        flash("Error inesperado al registrar la llave.")
        return redirect(url_for("webauthn.register"))
    # ────────────────────────────────────────────────────────────┘

    key = Key(
        user=current_user._get_current_object(),
        name=request.form["name"],
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=bytes_to_base64url(verification.credential_public_key),
        sign_count=verification.sign_count,
    )
    db.session.add(key)
    db.session.commit()
    flash("Llave registrada correctamente.")
    return redirect(url_for("webauthn.keys"))


@bp.route("/webauthn/login", methods=["GET", "POST"])
def login():
    user = load_user(session.get("user_id"))
    if not user:
        flash("Sesión webauthn expirada. Inicia sesión de nuevo.")
        return redirect(url_for("auth.login"))

    rp_id, origin = _rp_cfg()

    if request.method == "GET":
        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(k.credential_id))
                for k in user.keys
            ],
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )
        session["challenge"] = options.challenge
        return render_template("webauthn_login.html", options=options_to_json(options))

    # POST  ─────────────────────────────────────────────────────┐
    session.pop("user_id", None)           # ya no lo necesitamos

    try:
        credential = AuthenticationCredential.parse_raw(request.form["credential"])
        key = db.session.scalar(
            Key.select().where(Key.credential_id == credential.id)
        )

        if not key or key.user != user:
            flash("Llave no asociada a este usuario.")
            return redirect(url_for("main.index"))

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=session.pop("challenge"),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(key.public_key),
            credential_current_sign_count=key.sign_count,
            require_user_verification=False,
        )

    except wex.InvalidAuthenticationResponse as e:
        current_app.logger.warning("Autenticación WebAuthn inválida: %s", e)
        flash(f"Llave inválida: {e}")
        return redirect(url_for("main.index"))

    except Exception:
        _log_exc("Excepción inesperada en autenticación WebAuthn")
        flash("Error inesperado al verificar la llave.")
        return redirect(url_for("main.index"))
    # ────────────────────────────────────────────────────────────┘

    # Todo OK ➜ login
    login_user(user)
    key.sign_count = verification.new_sign_count
    key.last_used = time.time()
    db.session.commit()
    return redirect(url_for("main.index"))


@bp.route("/webauthn/delete", methods=["POST"])
@login_required
def delete():
    key = db.session.scalar(Key.select().where(Key.id == request.form["id"]))
    if not key or key.user != current_user:
        flash("No se pudo eliminar la llave.")
        return redirect(url_for("webauthn.keys"))

    db.session.delete(key)
    db.session.commit()
    flash("Llave eliminada.")
    return redirect(url_for("webauthn.keys"))
