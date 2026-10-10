"""
Application entry point for Vercel Flask framework deployment.
Exports the module-level WSGI 'app' object required by Vercel's Python runtime.
"""
from app import create_app

app = create_app()
