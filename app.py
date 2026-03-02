# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_login import LoginManager, login_required, current_user
from config import Config
from db import get_db_connection
from models import User
from utils import get_unread_messages
from flask_mail import Mail


app = Flask(__name__)
app.config.from_object(Config)

mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "auth.login"

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if row:
            return User(row['id'], row['username'], row['role'])
        return None
    finally:
        conn.close()

# Register Blueprints (we'll create these next)
from auth.routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

from vulnerable.routes import vuln_bp
app.register_blueprint(vuln_bp)

from monitor.routes import monitor_bp
app.register_blueprint(monitor_bp, url_prefix='/monitor')

from datetime import datetime


@app.context_processor
def inject_current_year():
    # make the current year available to all templates
    return {'current_year': datetime.utcnow().year}


@app.route("/")
def home():
    return render_template("home.html")


# Return unread messages for current user
@app.route('/messages/unread')
@login_required
def get_unread_messages_route():
    messages = get_unread_messages(current_user.id)
    return jsonify(messages)

# Mark a message as read
@app.route('/messages/mark-read/<int:msg_id>', methods=['POST'])
@login_required
def mark_message_read_route(msg_id):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    try:
        cursor.execute("UPDATE messages SET is_read=TRUE WHERE id=%s AND receiver_user_id=%s", 
                       (msg_id, current_user.id))
        conn.commit()
    except Exception as e:
        print(f"[MARK READ ERROR] {e}")
    finally:
        conn.close()
    return '', 204


if __name__ == "__main__":
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)

