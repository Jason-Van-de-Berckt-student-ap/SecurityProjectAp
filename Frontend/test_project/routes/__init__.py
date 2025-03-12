"""
Routes package for the EASM application.
This package contains all the route blueprints for the application.
"""
from flask import Blueprint

# Import all blueprints
from routes.single_scan import single_scan_bp
from routes.batch_scan import batch_scan_bp

# List of all blueprints for easy registration
all_blueprints = [
    single_scan_bp,
    batch_scan_bp
]