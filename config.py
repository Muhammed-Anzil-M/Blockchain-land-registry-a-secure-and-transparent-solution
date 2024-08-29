import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secrets.token_hex(16)'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://root:@localhost/land_reg'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
