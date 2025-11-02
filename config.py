
import os
from dotenv import load_dotenv

# تحميل المتغيرات البيئية من ملف .env
load_dotenv()


class Config:


    # إعدادات PDF
    PDF_ALLOWED_EXTENSIONS = {'pdf'}
    PDF_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB لملفات PDF

    # إعدادات APIs
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    METADEFENDER_API_KEY = os.getenv('METADEFENDER_API_KEY', '')
    # ... الإعدادات الحالية ...
    GOOGLE_OAUTH_CLIENT_ID = '93378653900-i9lo6160pfs0e2qmuik622tj7odvvh2h.apps.googleusercontent.com'
    GOOGLE_OAUTH_CLIENT_SECRET = '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'
    # إعدادات الأمان
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    SESSION_COOKIE_DOMAIN = None
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 ساعة

    # إعدادات قاعدة البيانات
    # config.py
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///malware_analysis.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # إعدادات التطبيق
    MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 ميجابايت
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp')
    ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'sys', 'scr', 'cpl'}
    DYNAMIC_ANALYSIS_ENABLED = os.getenv('DYNAMIC_ANALYSIS_ENABLED', 'true').lower() == 'true'

    # إعدادات الخادم
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))

    # إعدادات التقارير والنموذج
    REPORTS_FOLDER = os.getenv('REPORTS_FOLDER', os.path.join(os.getcwd(), 'reports'))
    MODEL_PATH = os.getenv('MODEL_PATH', 'baseline_rf_model_end.pkl')

    # إعدادات الساندبوكس
    SANDBOX_TIMEOUT = int(os.getenv('SANDBOX_TIMEOUT', 150))  # 5 دقائق