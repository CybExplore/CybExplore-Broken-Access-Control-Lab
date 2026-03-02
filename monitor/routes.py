# monitor/routes.py
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, jsonify
from config import Config
from db import get_db_connection, get_cursor
from utils import log_monitor_action, create_message, get_or_create_template


monitor_bp = Blueprint('monitor', __name__)

# ────────────────────────────────────────────────
# MONITOR LOGIN (separate from regular auth)
# ────────────────────────────────────────────────
@monitor_bp.route("/login", methods=["GET", "POST"])
def monitor_login():
    if session.get('is_monitor'):
        return redirect(url_for("monitor.dashboard"))

    if request.method == "GET":
        return render_template("monitor/monitor_login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if (username == Config.MONITOR_USERNAME and password == Config.MONITOR_PASSWORD):
        session['is_monitor'] = True
        # Optional: log your own login
        # log_monitor_action(
        #     user_id=None,
        #     username=username,
        #     action_type="monitor_login",
        #     details="Admin monitor session started",
        #     ip_address=request.remote_addr
        # )
        flash("Monitor access granted", "success")
        return redirect(url_for("monitor.dashboard"))
    else:
        flash("Invalid monitor credentials", "danger")
        return redirect(url_for("monitor.monitor_login"))

# ────────────────────────────────────────────────
# MONITOR LOGOUT
# ────────────────────────────────────────────────
@monitor_bp.route("/logout")
def monitor_logout():
    session.pop('is_monitor', None)
    flash("Monitor session ended", "info")
    return redirect(url_for("home"))

# ────────────────────────────────────────────────
# MONITOR DASHBOARD – Real-time activity view
# ────────────────────────────────────────────────
@monitor_bp.route("/dashboard")
def dashboard():
    if not session.get('is_monitor'):
        abort(403)  # or redirect to monitor_login

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)

        # Recent actions from monitor_logs (last 100)
        cursor.execute("""
            SELECT timestamp, username, action_type, target_id, details, ip_address
            FROM monitor_logs
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        logs = cursor.fetchall() or []

        # Quick stats
        cursor.execute("SELECT COUNT(*) AS count FROM monitor_logs WHERE action_type = 'login'")
        total_logins = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) AS count FROM monitor_logs WHERE action_type LIKE '%exploit%' OR action_type LIKE '%bypass%'")
        exploit_count = cursor.fetchone()['count']

        return render_template("monitor/dashboard.html",
                              logs=logs,
                              total_logins=total_logins,
                              exploit_count=exploit_count)

    except Exception as e:
        flash(f"Dashboard error: {str(e)}", "danger")
        return redirect(url_for("home"))
    finally:
        conn.close()

@monitor_bp.route("/logs-json")
def logs_json():
    if not session.get('is_monitor'):
        abort(403)

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT id, timestamp, username, action_type, target_id, details, ip_address
            FROM monitor_logs
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        logs = cursor.fetchall() or []
        
        # print(f"logs {logs}")
        # return jsonify({'logs': [dict(log) for log in logs]})

        # Convert datetime to string for JSON
        serialized_logs = []
        for log in logs:
            log_dict = dict(log)
            if isinstance(log_dict['timestamp'], datetime):
                log_dict['timestamp'] = log_dict['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            serialized_logs.append(log_dict)
        
        # print(f"serialized_logs {serialized_logs}")

        return jsonify({'logs': serialized_logs})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


# ────────────────────────────────────────────────
# SEND MESSAGE TO USER (Monitor-only route)
# ────────────────────────────────────────────────
from flask import request, jsonify, session, abort
from utils import create_message, get_or_create_template, log_monitor_action
from config import Config

@monitor_bp.route("/send-message", methods=["POST"])
def send_message():
    """
    Send a message to a user from the monitor dashboard.
    Supports optional reusable templates.
    """
    if not session.get('is_monitor'):
        abort(403)

    data = request.get_json()
    print(f"data: {data}")

    if not data:
        return jsonify({'success': False, 'error': 'Invalid JSON'}), 400

    # Required
    receiver_user_id = data.get('user_id')
    if not receiver_user_id:
        return jsonify({'success': False, 'error': 'Missing user_id'}), 400

    # Optional
    message_text = data.get('message', '').strip()
    template_key = data.get('template_key')

    sent_content = None
    success = False

    if template_key:
        template_id, template_content = get_or_create_template(
            template_key=template_key,
            title=data.get('template_title'),
            content=data.get('template_content')
        )

        if not template_content:
            return jsonify({'success': False, 'error': 'Template not found or invalid'}), 400

        # Append custom note
        if message_text:
            template_content += f"\n\nPersonal note: {message_text}"

        sent_content = template_content
        success = create_message(receiver_user_id, template_content, sender_role="monitor")

    else:
        if not message_text:
            return jsonify({'success': False, 'error': 'Missing message content'}), 400

        sent_content = message_text
        success = create_message(receiver_user_id, message_text, sender_role="monitor")

    if success:
        # Log action
        # log_monitor_action(
        #     user_id=None,
        #     username=Config.MONITOR_USERNAME,
        #     action_type="message_sent",
        #     target_id=receiver_user_id,
        #     details=f"Sent message to user {receiver_user_id}: {sent_content[:100]}...",
        #     ip_address=request.remote_addr
        # )
        return jsonify({
            'success': True,
            'message': 'Message sent successfully',
            'sent_content': sent_content[:200]
        })

    return jsonify({'success': False, 'error': 'Failed to send message (DB error)'}), 500


@monitor_bp.route("/latest-alert")
def latest_alert():
    if not session.get('is_monitor'):
        abort(403)

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT id, username, action_type, details
            FROM monitor_logs
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        latest = cursor.fetchone()
        if latest:
            return jsonify(dict(latest))
        return jsonify({})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

