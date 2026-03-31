import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend', 'api'))

from flask import Flask
app = Flask(__name__)

try:
    from app import app
except Exception as e:
    print(f"Import error: {e}")

@app.route('/health')
def health():
    return {"status": "ok"}

@app.route('/')
def home():
    return {"status": "ok"}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)