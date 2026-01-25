"""
Routes module for Sentinel Logger
"""
from flask import Blueprint

# Create blueprints
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# Import route handlers
from app.routes import views
from app.routes import api
