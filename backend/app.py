from flask import Flask
from flask_cors import CORS
from config import config
import os

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    # Enable CORS
    CORS(app)
    
    # Create the uploads directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'] , exist_ok=True)
    
    # Register blueprints
    from routes.routes import upload_routes
    from routes.dynamic_sandboxing import dynamic_routes
    app.register_blueprint(upload_routes)
    app.register_blueprint(dynamic_routes)
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)