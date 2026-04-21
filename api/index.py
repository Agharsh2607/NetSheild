"""
Vercel WSGI entry point for NetShield AI
"""
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set Vercel environment flag before importing app
os.environ['VERCEL'] = '1'

from app import app

# Vercel handler function
def handler(environ, start_response):
    return app(environ, start_response)

# Export the app for Vercel
application = app

# For local testing
if __name__ == "__main__":
    app.run(debug=True)