import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    ALCHEMICAL_DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')


    WEBAUTHN_RP_NAME = 'Flask WebAuthn Demo'

    # config.py (o donde toque)
    WEBAUTHN_RP_ID       = "ubiquitous-garbanzo-w476wjv9qj929rpp-5000.app.github.dev"
    WEBAUTHN_RP_ORIGIN   = "https://ubiquitous-garbanzo-w476wjv9qj929rpp-5000.app.github.dev"
