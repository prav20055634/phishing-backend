import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend', 'api'))

from app import app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)