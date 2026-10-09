"""
Vercel Serverless Function entry point for Data Leak Guardian.
Exports the module-level WSGI 'app' object required by Vercel's Python runtime.
"""
from app import create_app

app = create_app()
