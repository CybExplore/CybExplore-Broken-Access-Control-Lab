# auth/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import uuid
from config import Config
from db import get_db_connection, get_cursor
from models import User
from utils import log_monitor_action

auth_bp = Blueprint('auth', __name__)

# ────────────────────────────────────────────────
# REGISTER – Mass Assignment Vulnerability
# ────────────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("Already logged in", "info")
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("auth/register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "user")  # MASS ASSIGNMENT VULN

    if not username or not password:
        flash("Username and password required", "danger")
        return redirect(url_for("auth.register"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            flash("Username taken", "danger")
            return redirect(url_for("auth.register"))

        user_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO users (id, username, password, email, role)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, username, password, email or None, role))
        conn.commit()

        # Log only if role was tampered to something privileged
        if role != "user":
            log_monitor_action(
                user_id=user_id,
                username=username,
                action_type="register_role_tamper",
                target_id=user_id,
                details=f"Registered with tampered role: {role}",
                ip_address=request.remote_addr
            )

        flash("Registered! Log in now.", "success")
        return redirect(url_for("auth.login"))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("auth.register"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# LOGIN
# ────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("auth/login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT id, username, password, role, email, phone, hostel, bio
            FROM users WHERE username = %s
        """, (username,))
        row = cursor.fetchone()

        if row and row['password'] == password:
            user = User(
                id=row['id'],
                username=row['username'],
                password=row['password'],
                email=row['email'],
                phone=row.get('phone'),
                hostel=row.get('hostel'),
                bio=row.get('bio'),
                role=row['role']
            )
            login_user(user, remember=True)

            # Log successful login (always log logins – useful for session tracking)
            log_monitor_action(
                user_id=user.id,
                username=user.username,
                action_type="login",
                details="Successful login",
                ip_address=request.remote_addr
            )

            flash(f"Welcome, {user.username}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for("auth.login"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# LOGOUT
# ────────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    # Log logout (useful for session tracking)
    log_monitor_action(
        user_id=current_user.id,
        username=current_user.username,
        action_type="logout",
        details="User logged out",
        ip_address=request.remote_addr
    )
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("home"))

# ────────────────────────────────────────────────
# FORGOT PASSWORD
# ────────────────────────────────────────────────
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        flash("Already logged in", "info")
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("auth/forgot.html")

    identifier = request.form.get("identifier", "").strip()

    if not identifier:
        flash("Enter username or email", "danger")
        return redirect(url_for("auth.forgot_password"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT id, username, email 
            FROM users 
            WHERE username = %s OR email = %s
        """, (identifier, identifier))
        user_data = cursor.fetchone()

        if user_data:
            user = User(id=user_data['id'], username=user_data['username'], email=user_data['email'])
            token = user.generate_reset_token()

            cursor.execute("""
                UPDATE users 
                SET reset_token = %s, reset_token_expiry = DATE_ADD(NOW(), INTERVAL 30 MINUTE)
                WHERE id = %s
            """, (token, user.id))
            conn.commit()

            reset_url = url_for("auth.reset_password", token=token, _external=True)

            # SMTP integration (debug or real)
            from flask_mail import Message
            msg = Message(
                subject="CybExplore Lab - Password Reset",
                recipients=[user.email] if user.email else [f"{user.username}@localhost"],
                body=f"Hello {user.username},\n\nReset your password here:\n{reset_url}\n\nExpires in 30 minutes.\n\nIgnore if not requested.",
                sender=Config.MAIL_DEFAULT_SENDER
            )

            if Config.MAIL_DEBUG_ONLY:
                print("\n" + "="*70)
                print(f"WOULD SEND TO: {msg.recipients}")
                print(f"SUBJECT: {msg.subject}")
                print(f"BODY:\n{msg.body}")
                print(f"RESET LINK: {reset_url}")
                print("="*70 + "\n")
                flash("Reset link generated (check console)", "info")
            else:
                try:
                    from app import mail
                    mail.send(msg)
                    flash("Reset link sent to your email", "success")
                except Exception as e:
                    print(f"Mail error: {str(e)}")
                    flash("Failed to send email", "danger")

            # # Log the reset request (potential reconnaissance)
            # log_monitor_action(
            #     user_id=user.id,
            #     username=user.username,
            #     action_type="forgot_password_request",
            #     target_id=user.id,
            #     details=f"Password reset requested for {user.username}",
            #     ip_address=request.remote_addr
            # )
        else:
            flash("No account found", "danger")  # existence leak – intentional

        return redirect(url_for("auth.login"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# RESET PASSWORD
# ────────────────────────────────────────────────
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user_id = User.verify_reset_token(token)
    if not user_id:
        flash("Invalid or expired reset link", "danger")
        return redirect(url_for("auth.forgot_password"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if not user_data:
            flash("User not found", "danger")
            return redirect(url_for("auth.forgot_password"))

        if request.method == "GET":
            return render_template("auth/reset.html", token=token)

        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not new_password or new_password != confirm_password:
            flash("Passwords do not match or are empty", "danger")
            return redirect(url_for("auth.reset_password", token=token))

        cursor.execute("""
            UPDATE users 
            SET password = %s, reset_token = NULL, reset_token_expiry = NULL
            WHERE id = %s
        """, (new_password, user_id))
        conn.commit()

        # # Log successful reset (potential takeover if token was stolen)
        # log_monitor_action(
        #     user_id=user_id,
        #     username=user_data['username'],
        #     action_type="password_reset_success",
        #     target_id=user_id,
        #     details="Password reset completed via token",
        #     ip_address=request.remote_addr
        # )

        flash("Password has been reset. Please log in.", "success")
        return redirect(url_for("auth.login"))

    finally:
        conn.close()

# ────────────────────────────────────────────────
# CHANGE PASSWORD – Logged-in user
# ────────────────────────────────────────────────
@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("auth/change_password.html")

    old_password = request.form.get("old_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_new = request.form.get("confirm_new", "").strip()
    target_user_id = request.form.get("user_id", current_user.id)  # hidden field for IDOR demo

    if not old_password or not new_password or new_password != confirm_new:
        flash("Invalid input or passwords don't match", "danger")
        return redirect(url_for("auth.change_password"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)

        # --- Fetch stored password for target ---
        cursor.execute("SELECT password FROM users WHERE id = %s", (target_user_id,))
        stored = cursor.fetchone()

        if not stored:
            flash("Target user not found", "danger")
            return redirect(url_for("auth.change_password"))

        # --- Detect cross-account attempt ---
        if target_user_id != current_user.id:
            flash("Trying to change someone else's password? (vuln demo)", "warning")

            # Log ONLY cross-account attempt (your request!)
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="change_password_attempt",
                target_id=target_user_id,
                details=f"Attempted password change on user {target_user_id} (possible IDOR)",
                ip_address=request.remote_addr
            )
            return redirect(url_for("auth.change_password"))

        cursor.execute("""
            UPDATE users SET password = %s WHERE id = %s
        """, (new_password, target_user_id))
        conn.commit()

        flash("Password changed successfully", "success")
        return redirect(url_for("home"))

    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("auth.change_password"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# CHANGE EMAIL – Logged-in user (with target_id for IDOR)
# ────────────────────────────────────────────────
@auth_bp.route("/change-email", methods=["GET", "POST"])
@login_required
def change_email():
    if request.method == "GET":
        return render_template("auth/change_email.html", current_email=current_user.email)

    new_email = request.form.get("new_email", "").strip()
    # Vulnerable: optional hidden field for IDOR/mass assignment
    target_user_id = request.form.get("user_id", current_user.id)

    if not new_email:
        flash("Please enter a new email", "danger")
        return redirect(url_for("auth.change_email"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)

        # VULN: no real ownership check
        if target_user_id != current_user.id:
            flash("Trying to change someone else's email? (vuln demo)", "warning")

            # Log ONLY cross-account attempt (your request!)
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="change_email_attempt",
                target_id=target_user_id,
                details=f"Attempted email change on user {target_user_id} (possible IDOR/mass assignment)",
                ip_address=request.remote_addr
            )

        # Check email uniqueness (existence leak)
        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, target_user_id))
        if cursor.fetchone():
            flash("Email already in use", "danger")
            return redirect(url_for("auth.change_email"))

        cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, target_user_id))
        conn.commit()

        flash(f"Email updated to {new_email} (no verification needed!)", "success")
        return redirect(url_for("home"))

    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("auth.change_email"))
    finally:
        conn.close()
