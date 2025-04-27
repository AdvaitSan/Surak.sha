import os
from datetime import timedelta

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    
    # MongoDB configuration
    MONGO_URI = os.environ.get('mongodb+srv://aadityamalani15:yHFOhT72LbpT052L@cluster0.cu7v1af.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0') or 'mongodb://localhost:27017/'
    MONGO_DB_NAME = os.environ.get('local') or 'file_scanner'
    
    # VirusTotal configuration
    VT_API_KEY = os.environ.get('ed85f6612c26d917c173df1a8547df9df0d9f114eaf1b73d15cd4e59558bf4da') or 'ed85f6612c26d917c173df1a8547df9df0d9f114eaf1b73d15cd4e59558bf4da'
    
    # Other configurations
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
    
    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    MONGO_DB_NAME = 'file_scanner_test'

class ProductionConfig(Config):
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        # Log to syslog
        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}