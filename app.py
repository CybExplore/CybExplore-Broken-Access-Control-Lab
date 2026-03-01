# app.py
from flask import Flask
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Register blueprints (modular directories)
from auth.routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

from vulnerable.routes import vuln_bp
app.register_blueprint(vuln_bp)  # No prefix – main app

from monitor.routes import monitor_bp
app.register_blueprint(monitor_bp, url_prefix='/monitor')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
