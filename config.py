import secrets

class Config:
    SECRET_KEY = secrets.token_hex(16)
    DATABASE = '/home/SireApp/sireapp/sireapp.db'
    MAIL_API_KEY = "485730ec628217d066aacd3b5b426415-6df690bb-b451793d"
    MAIL_DOMAIN = "sandbox5daafeb6b7bc4451a127d28c173c7d3d.mailgun.org"
    MAIL_SERVER = "live.smtp.mailtrap.io"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = "api"
    MAIL_PASSWORD = "b954472180f797a68cdfb8bc2dd116b9"
    MAIL_DEFAULT_SENDER = "noreply.sireapp@sammie.ie"
    DEBUG_MODE = True