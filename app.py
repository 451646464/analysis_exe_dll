import os
import json
import logging
import re
import tempfile
from flask import session
import random
from fpdf import FPDF
import string
import plotly.graph_objects as go
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
import joblib
import requests
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, flash, jsonify, abort
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from sandbox import Sandbox
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database import db, init_db
from models import User, AnalysisSample, WebAnalysis, OAuth, CodeAnalysis, ImageAnalysis, UserSettings
from utils import (
    allowed_file_exe, calculate_file_hash, extract_pe_features,
    predict_sample, generate_pdf_report, create_share_link, safe_delete, extract_strings, run_binwalk, analyze_entropy,
    analyze_network_indicators, apply_yara_rules, extract_libraries, extract_powershell_commands,
    analyze_persistence_mechanisms, detect_c2_servers, detect_packing, mitre_attck_mapping
)
import sys
import io

from web_analysis import analyze_url_web, extract_links, SEVERITY_LEVELS

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
# تهيئة التطبيق
app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_COOKIE_SECURE'] = False  # أضف هذا السطر
app.config['SESSION_COOKIE_DOMAIN'] = None   #
# في أعلى app.py بعد الاستيرادات
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# أو إذا كنت تستخدم Flask-WTF بالفعل، تأكد من تفعيل حماية CSRF
init_db(app)
# تهيئة نظام تسجيل الدخول
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# أضف هذه الاستيرادات في الأعلى

# إعدادات جوجل OAuth
app.config['GOOGLE_OAUTH_CLIENT_ID'] ='93378653900-i9lo6160pfs0e2qmuik622tj7odvvh2h.apps.googleusercontent.com'
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = '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'
# إعدادات إضافية
app.config['ML_MODEL_PATH'] = 'models/image_malware_model.h5'  # مسار نموذج تعلم الآلة

# إنشاء مجلد النماذج إذا لم يكن موجوداً
os.makedirs('models', exist_ok=True)
# إنشاء blueprint للتسجيل عبر جوجل
google_bp = make_google_blueprint(
    scope=["profile", "email"],
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user),
    redirect_to='dashboard'
)

app.register_blueprint(google_bp, url_prefix="/login")
# بعد تعريف load_ml_models()
# إعدادات البريد الإلكتروني
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rakanalmoliki33@gmail.com'
app.config['MAIL_PASSWORD'] = 'pqiz ooxk jfpa huvo'
app.config['MAIL_DEFAULT_SENDER'] = 'rakanalmoliki33@gmail.com'
app.config['MAIL_USE_SSL'] = False  # أضف هذا السطر
app.config['MAIL_DEBUG'] = True

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]

    # البحث عن OAuth في قاعدة البيانات
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            token=token,
        )

    if oauth.user:
        login_user(oauth.user)
        flash("Successfully signed in with Google.")
    else:
        # إنشاء مستخدم جديد
        user = User(
            username=google_info["email"].split("@")[0],
            email=google_info["email"],
            is_verified=True
        )
        oauth.user = user
        db.session.add_all([user, oauth])
        db.session.commit()
        login_user(user)
        flash("Successfully signed up with Google.")

    return False

# معالج لأخطاء OAuth
@oauth_error.connect_via(google_bp)
def google_error(blueprint, error, error_description=None, error_uri=None):
    msg = (
        f"OAuth error from {blueprint.name}! "
        f"error={error} description={error_description} uri={error_uri}"
    )
    flash(msg, category="error")
# توليد كابتشا
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    return captcha_text


# إرسال البريد الإلكتروني
def send_verification_email(email, token):
    try:
        verification_link = url_for('verify_email', token=token, _external=True)
        subject = "تأكيد حسابك في نظام تحليل البرمجيات"
        body = f"مرحباً،\n\nالرجاء الضغط على الرابط التالي لتأكيد حسابك:\n{verification_link}"

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = email

        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"خطأ في إرسال البريد: {str(e)}")
        return False


# تحديث مسار التسجيل
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        captcha_input = request.form.get('captcha')
        captcha_session = session.get('captcha', '')

        # التحقق من الكابتشا
        if captcha_input != captcha_session:
            flash('Invalid CAPTCHA code', 'error')
            return render_template('signup.html', captcha=generate_captcha())

        # التحقق من كلمة المرور
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html', captcha=generate_captcha())

        # التحقق من وجود المستخدم
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('signup.html', captcha=generate_captcha())

        # إنشاء المستخدم
        hashed_password = generate_password_hash(password)
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            verification_token=token
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            # إرسال بريد التفعيل
            if send_verification_email(email, token):
                flash('Account created successfully! Please check your email to verify your account.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Error sending verification email. Please try again later.', 'error')
                return render_template('signup.html', captcha=generate_captcha())

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')
            app.logger.error(f"Error creating account: {str(e)}")

    return render_template('signup.html', captcha=generate_captcha())

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('تم تفعيل حسابك بنجاح! يمكنك تسجيل الدخول الآن', 'success')
    else:
        flash('رابط التفعيل غير صالح أو منتهي الصلاحية', 'error')
    return redirect(url_for('login'))


# تحديث مسار الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Your account is not verified. Please check your email.', 'error')
                return redirect(url_for('login'))

            login_user(user)
            user.update_last_login()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')




# —————— هنا أضف فلتر hex المخصص ——————
@app.template_filter('hex')
def hex_filter(value):
    try:
        return hex(int(value))
    except (ValueError, TypeError):
        return '0x0'
@app.template_filter('yesno')
def yesno_filter(value, true_label='نعم', false_label='لا'):
    """
    يحول القيم المنطقية إلى نص عربي:
    True  → 'نعم'
    False → 'لا'
    أي قيمة أخرى → ''
    """
    if value is True:
        return true_label
    if value is False:
        return false_label
    return ''
# تهيئة نظام تسجيل الأخطاء
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# ملف السجلات
file_handler = RotatingFileHandler('malware_analysis.log', maxBytes=1024 * 1024 * 10, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)

# وحدة التحكم
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.DEBUG)

app.logger.addHandler(file_handler)
app.logger.addHandler(stream_handler)
app.logger.setLevel(logging.DEBUG)

# تهيئة قاعدة البيانات



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# معالج السياق لتوفير المتغير 'now' لجميع القوالب
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}
############################################[ image analysis ]##############################################

from datetime import datetime, timezone, timedelta
from flask import render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from sqlalchemy import func
from models import User, AnalysisSample, WebAnalysis, URLAnalysis, PDFAnalysis, CodeAnalysis, ImageAnalysis
from image_analyzer import analyze_image_comprehensive, calculate_file_hash
import os
from werkzeug.utils import secure_filename

# استيراد المكونات الجديدة
from advanced_phishing_detector import AdvancedPhishingDetector
from behavioral_analyzer import BehavioralImageAnalyzer
from threat_intelligence import ThreatIntelligenceIntegration

# التكوين
UPLOAD_FOLDER = 'uploads/images'
ALLOWED_EXTENSIONS_IMAGE = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'}
# التكوين
THREAT_INTELLIGENCE_CONFIG = {
    'virustotal_api_key': '4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e',
    'alienvault_api_key': '0a14a6aacec60c7f9fe9488f8ba2c1a28a8fc08b9f5b42a735ac6c017f94d146',
    'google_safe_browsing_api_key': 'your_google_safe_browsing_api_key_here',
}

# نقل المفاتيح إلى إعدادات التطبيق
app.config['VIRUSTOTAL_API_KEY'] = THREAT_INTELLIGENCE_CONFIG['virustotal_api_key']
app.config['ALIENVAULT_API_KEY'] = THREAT_INTELLIGENCE_CONFIG['alienvault_api_key']
app.config['GOOGLE_SAFE_BROWSING_API_KEY'] = THREAT_INTELLIGENCE_CONFIG['google_safe_browsing_api_key']

# تهيئة المكونات
phishing_detector = AdvancedPhishingDetector()
behavioral_analyzer = BehavioralImageAnalyzer()
threat_intelligence = ThreatIntelligenceIntegration(THREAT_INTELLIGENCE_CONFIG)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size


def allowed_file_image(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGE


@app.route('/analyze_image', methods=['GET', 'POST'])
@login_required
def analyze_image():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        if file and allowed_file_image(file.filename):
            # حفظ الملف مؤقتًا
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.save(file_path)

            try:
                # تحميل نموذج تعلم الآلة (إذا كان متوفراً)
                ml_model = None
                try:
                    from ml_image_analyzer import ImageMalwareDetector
                    model_path = app.config.get('ML_MODEL_PATH')
                    if model_path and os.path.exists(model_path):
                        ml_model = ImageMalwareDetector(model_path)
                    else:
                        ml_model = None
                        app.logger.warning("نموذج تعلم الآلة غير موجود. سيتم تخطي تحليل تعلم الآلة.")
                except ImportError as e:
                    ml_model = None
                    app.logger.warning(f"لا يمكن تحميل وحدة تحليل تعلم الآلة: {e}")

                # تحليل الصورة مع الميزات الجديدة
                virustotal_api_key = app.config.get('VIRUSTOTAL_API_KEY')
                result = analyze_image_comprehensive(
                    file_path,
                    virustotal_api_key,
                    ml_model,
                    phishing_detector,
                    behavioral_analyzer,
                    threat_intelligence
                )

                # تسجيل النتائج للتdebug
                app.logger.info(f"نتائج التحليل: {result}")

                # حفظ النتائج في قاعدة البيانات
                new_analysis = ImageAnalysis(
                    user_id=current_user.id,
                    filename=filename,
                    file_hash=calculate_file_hash(file_path),
                    file_size=os.path.getsize(file_path),
                    is_malicious=result['is_malicious'],
                    threat_score=result['threat_score'],
                    threat_type=result['threat_type']
                )
                new_analysis.set_analysis_results(result)
                db.session.add(new_analysis)
                db.session.commit()

                return render_template('image_analysis_result.html',
                                       analysis=new_analysis,
                                       results=result)

            except Exception as e:
                flash(f'خطأ في تحليل الصورة: {str(e)}', 'error')
                app.logger.error(f"خطأ في تحليل الصورة: {str(e)}", exc_info=True)
                return render_template('analyze_image.html')

            finally:
                # تنظيف الملف المؤقت
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        app.logger.error(f"خطأ في حذف الملف المؤقت: {str(e)}")

        else:
            flash('نوع الملف غير مسموح به', 'error')
            return render_template('analyze_image.html')

    return render_template('analyze_image.html')


@app.route('/image_report/<int:analysis_id>')
@login_required
def image_report(analysis_id):
    try:
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        app.logger.info(f"تم العثور على تحليل الصورة: {analysis_id}")

        # تحقق من أن المستخدم لديه صلاحية عرض التقرير
        if not current_user.is_admin and analysis.user_id != current_user.id:
            app.logger.warning(f"المستخدم غير مصرح له بالوصول إلى تحليل الصورة: {analysis_id}")
            abort(403)

        # استرجاع نتائج التحليل من قاعدة البيانات
        results = analysis.get_analysis_results()

        # تسجيل معلومات التdebug
        app.logger.info(f"تحليل الصورة {analysis_id}: exists={analysis is not None}")
        app.logger.info(f"تحليل الصورة {analysis_id}: analysis_results exists={analysis.analysis_results is not None}")
        app.logger.info(f"تحليل الصورة {analysis_id}: results type={type(results)}")

        if not results:
            app.logger.warning(f"لا توجد نتائج لتحليل الصورة: {analysis_id}")
            flash('لا توجد نتائج تحليل لهذه الصورة', 'error')
            return redirect(url_for('dashboard'))

        return render_template('image_analysis_result.html',
                               analysis=analysis,
                               results=results)

    except Exception as e:
        app.logger.error(f"خطأ في تحميل تقرير الصورة {analysis_id}: {str(e)}")
        flash('حدث خطأ في تحميل التقرير', 'error')
        return redirect(url_for('dashboard'))






############################################[ web analysis ]##############################################
@app.route('/web_analysis', methods=['GET', 'POST'])
@login_required
def web_analysis():
    """تحليل شامل لتطبيقات الويب لاكتشاف الثغرات الأمنية"""
    if request.method == 'POST':
        try:
            # استقبال البيانات من النموذج
            scan_type = request.form.get('scan_type', 'single')
            target = request.form.get('target', '').strip()
            max_pages = int(request.form.get('max_pages', 20))

            # التحقق من صحة الرابط المدخل
            if not target:
                flash('يجب إدخال رابط صحيح', 'danger')
                return redirect(url_for('web_analysis'))

            # إضافة البروتوكول إذا لم يكن موجوداً
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target

            # تحليل الرابط والتأكد من صحته
            parsed = urlparse(target)
            if not parsed.netloc:
                flash('الرابط المدخل غير صحيح', 'danger')
                return redirect(url_for('web_analysis'))

            domain = parsed.netloc
            start_time = datetime.now()

            # تسجيل بدء عملية الفحص
            app.logger.info(f"بدء فحص الرابط: {target} | نوع الفحص: {scan_type}")

            # عملية الفحص حسب النوع
            if scan_type == 'single':
                # فحص رابط واحد
                report = analyze_url_web(target)
                scan_data = {
                    "domain": domain,
                    "scan_type": "رابط واحد",
                    "total_links": 1,
                    "vulnerable_links": 1 if report["vulnerabilities"] else 0,
                    "vulnerabilities": report["vulnerabilities"],
                    "stats": report["stats"],
                    "target_url": target
                }
            else:
                # فحص كامل النطاق
                links = extract_links(target, max_pages)

                if not links:
                    flash('لم يتم العثور على روابط تحتوي على معلمات للفحص', 'warning')
                    return redirect(url_for('web_analysis'))

                scan_data = {
                    "domain": domain,
                    "scan_type": "نطاق كامل",
                    "total_links": len(links),
                    "vulnerable_links": 0,
                    "vulnerabilities": [],
                    "stats": {"total_tests": 0, "vulnerable": 0},
                    "target_url": target
                }

                # فحص جميع الروابط المستخرجة
                for i, link in enumerate(links, 1):
                    try:
                        app.logger.info(f"جاري فحص الرابط {i}/{len(links)}: {link}")
                        report = analyze_url(link)

                        if report["vulnerabilities"]:
                            scan_data["vulnerable_links"] += 1
                            scan_data["vulnerabilities"].extend(report["vulnerabilities"])

                        scan_data["stats"]["total_tests"] += report["stats"]["total_tests"]
                        scan_data["stats"]["vulnerable"] += report["stats"]["vulnerable"]

                    except Exception as e:
                        app.logger.error(f"خطأ أثناء فحص الرابط {link}: {str(e)}")
                        continue

            # حساب مدة الفحص
            duration = datetime.now() - start_time
            scan_data["duration"] = str(duration)

            # حفظ النتائج في قاعدة البيانات
            web_analysis = WebAnalysis(
                domain=domain,
                scan_type=scan_type,
                total_links=scan_data["total_links"],
                vulnerable_links=scan_data["vulnerable_links"],
                user_id=current_user.id,
                scan_date=datetime.now()
            )

            web_analysis.set_vulnerabilities(scan_data["vulnerabilities"])
            db.session.add(web_analysis)
            db.session.commit()

            # عرض النتائج
            flash(f"تم الانتهاء من الفحص بنجاح! الوقت المستغرق: {duration}", 'success')
            return render_template(
                'web_report.html',
                scan_data=scan_data,
                SEVERITY_LEVELS=SEVERITY_LEVELS,
                analysis_id=web_analysis.id
            )

        except Exception as e:
            db.session.rollback()
            error_msg = f'حدث خطأ أثناء فحص الرابط: {str(e)}'
            app.logger.error(error_msg)
            flash(error_msg, 'danger')
            return redirect(url_for('web_analysis'))

    # عرض صفحة الفحص إذا كانت الطريقة GET
    return render_template('web_analysis.html')


@app.route('/web_report/<int:analysis_id>')
@login_required
def web_analysis_report(analysis_id):
    try:
        analysis = WebAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('dashboard'))

        # حساب الروابط الآمنة
        safe_links = analysis.total_links - analysis.vulnerable_links

        # إنشاء هيكل البيانات المتوقع في القالب
        scan_data = {
            "domain": analysis.domain,
            "scan_type": "نطاق كامل" if analysis.scan_type == "full" else "رابط واحد",
            "stats": {
                "total": analysis.total_links,
                "vulnerable": analysis.vulnerable_links,
                "safe": safe_links
            },
            "vulnerabilities": analysis.get_vulnerabilities(),
            "scan_date": analysis.scan_date.strftime("%Y-%m-%d %H:%M:%S")
        }

        return render_template(
            'web_report.html',
            scan_data=scan_data,
            SEVERITY_LEVELS=SEVERITY_LEVELS,
            analysis_id=analysis.id
        )
    except Exception as e:
        app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
        flash('حدث خطأ أثناء تحميل التقرير', 'danger')
        return redirect(url_for('dashboard'))
# Flask مثال لتنفيذ نقاط النهاية في

@app.route('/generate_web_pdf/<scan_id>')
def generate_web_pdf(scan_id):
    # الكود الخاص بإنشاء ملف PDF لتقرير الويب
    pass

@app.route('/share_web_scan/<scan_id>', methods=['POST'])
def share_web_scan(scan_id):
    # الكود الخاص بمشاركة تقرير الويب
    pass





############################################[ pdf analysis ]##############################################
# إضافة الاستيرادات اللازمة
import PyPDF2
import pdfplumber
from pdfminer.high_level import extract_text

# إضافة بعد استيرادات أخرى
from models import PDFAnalysis  # تأكد من إضافة هذا


# وظائف تحليل PDF
def extract_pdf_metadata(file_path):
    """استخراج metadata من ملف PDF"""
    metadata = {}
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            metadata = pdf_reader.metadata
    except Exception as e:
        app.logger.error(f"خطأ في استخراج metadata: {str(e)}")
    return metadata


def extract_pdf_text(file_path):
    """استخراج النص من ملف PDF"""
    try:
        text = extract_text(file_path)
        return text
    except Exception as e:
        app.logger.error(f"خطأ في استخراج النص: {str(e)}")
        return ""


def analyze_pdf_structure(file_path):
    """تحليل هيكل PDF"""
    structure_info = {
        'pages': 0,
        'forms': False,
        'javascript': False,
        'embedded_files': False
    }

    try:
        with pdfplumber.open(file_path) as pdf:
            structure_info['pages'] = len(pdf.pages)

            # تحليل كل صفحة
            for page in pdf.pages:
                if page.annots:
                    structure_info['forms'] = True
                if '/JS' in str(page) or '/JavaScript' in str(page):
                    structure_info['javascript'] = True
                if '/EmbeddedFiles' in str(page):
                    structure_info['embedded_files'] = True

    except Exception as e:
        app.logger.error(f"خطأ في تحليل الهيكل: {str(e)}")

    return structure_info


# وظائف APIs لفحص PDF
def scan_with_virustotal(file_path, api_key):
    """فحص الملف باستخدام VirusTotal API"""
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        files = {'file': (file_path, open(file_path, 'rb'))}
        params = {'apikey': api_key}

        response = requests.post(url, files=files, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        return {'error': str(e)}


def scan_with_metadefender(file_path, api_key):
    """فحص الملف باستخدام MetaDefender API"""
    try:
        url = 'https://api.metadefender.com/v4/file'
        headers = {'apikey': api_key}
        files = {'file': open(file_path, 'rb')}

        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'HTTP {response.status_code}'}
    except Exception as e:
        return {'error': str(e)}


# مسار تحليل PDF
@app.route('/pdf_analysis', methods=['GET', 'POST'])
@login_required
def pdf_analysis():
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        file = request.files['pdf_file']
        if file.filename == '':
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        if not file.filename.lower().endswith('.pdf'):
            flash('صيغة غير مدعومة، اختر ملف PDF', 'error')
            return redirect(request.url)
        from datetime import datetime, timezone
        # حفظ الملف مؤقتاً
        temp_dir = tempfile.gettempdir()
        temp_filename = f"pdf_analysis_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}.pdf"
        file_path = os.path.join(temp_dir, temp_filename)

        try:
            file.save(file_path)
        except Exception as e:
            flash(f'خطأ في حفظ الملف: {str(e)}', 'error')
            return redirect(request.url)

        # حساب hash وحجم الملف
        try:
            file_size = os.path.getsize(file_path)
            file_hash = calculate_file_hash(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في قراءة الملف: {str(e)}', 'error')
            return redirect(request.url)

        filename = secure_filename(file.filename)

        # التحقق من وجود تحليل سابق
        existing_analysis = PDFAnalysis.query.filter_by(file_hash=file_hash).first()
        if existing_analysis:
            safe_delete(file_path)
            flash('تم تحليل هذا الملف سابقاً', 'info')
            return redirect(url_for('pdf_report', analysis_id=existing_analysis.id))

        # تحليل PDF
        try:
            # تسجيل وقت البدء
            start_time = datetime.now(timezone.utc)

            # استخراج metadata والنص
            metadata = extract_pdf_metadata(file_path)
            text_content = extract_pdf_text(file_path)
            structure_info = analyze_pdf_structure(file_path)

            # فحص باستخدام APIs
            selected_engines = request.form.getlist('engines')
            api_results = {}

            if 'virustotal' in selected_engines:
                vt_api_key = "4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e"
                api_results['virustotal'] = scan_with_virustotal(file_path, vt_api_key)

            if 'metadefender' in selected_engines:
                md_api_key = "c0d6959e3e9cfa4130581d909925fe6f"
                api_results['metadefender'] = scan_with_metadefender(file_path, md_api_key)

            # تحليل النص لاكتشاف التهديدات
            threats = analyze_pdf_content(text_content)

            # تحديد إذا كان الملف ضاراً
            is_malicious = any(engine_result.get('detected', False) for engine_result in api_results.values()) or len(
                threats) > 0

            # حساب مدة الفحص
            end_time = datetime.now(timezone.utc)
            scan_duration = end_time - start_time

            # حفظ النتائج في قاعدة البيانات
            pdf_analysis = PDFAnalysis(
                user_id=current_user.id,
                filename=filename,
                file_hash=file_hash,
                file_size=file_size,
                is_malicious=is_malicious,
                threat_score=calculate_threat_score(api_results, threats),
                engines_used=json.dumps(selected_engines),
                engines_total=len(selected_engines),
                engines_detected=sum(1 for r in api_results.values() if r.get('detected', False)),
                upload_date=datetime.now(timezone.utc),
                scan_date=datetime.now(timezone.utc)
            )

            pdf_analysis.set_results(api_results)
            pdf_analysis.set_vulnerabilities(threats)
            pdf_analysis.set_file_metadata({
                'metadata': metadata,
                'structure': structure_info,
                'text_length': len(text_content),
                'scan_duration': str(scan_duration)
            })

            db.session.add(pdf_analysis)
            db.session.commit()

            safe_delete(file_path)
            flash('تم تحليل الملف بنجاح!', 'success')
            return redirect(url_for('pdf_report', analysis_id=pdf_analysis.id))

        except Exception as e:
            safe_delete(file_path)
            # معالجة الأخطاء مع دعم اللغة العربية
            error_msg = f'خطأ في تحليل الملف: {str(e)}'
            try:
                app.logger.error(error_msg)
            except UnicodeEncodeError:
                # إذا فشل التسجيل بسبب مشاكل الترميز
                app.logger.error(error_msg.encode('utf-8').decode('latin-1'))
            flash(error_msg, 'error')
            return redirect(request.url)

    return render_template('pdf_analysis.html')
# مسار تقرير PDF
@app.route('/pdf_report/<int:analysis_id>')
@login_required
def pdf_report(analysis_id):
    try:
        analysis = PDFAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('dashboard'))

        # الحصول على البيانات من النموذج - استخدام الدالة الجديدة
        results = analysis.get_results()
        vulnerabilities = analysis.get_vulnerabilities()
        file_metadata = analysis.get_file_metadata()  # تغيير هنا

        # تمرير البيانات للقالب
        return render_template(
            'pdf_report.html',
            analysis=analysis,
            results=results,
            vulnerabilities=vulnerabilities,
            file_metadata=file_metadata  # تغيير هنا أيضاً
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'error')
        return redirect(url_for('pdf_analysis'))


@app.route('/delete_pdf_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_pdf_report(analysis_id):
    try:
        analysis = PDFAnalysis.query.get_or_404(analysis_id)

        # التحقق من صلاحية المستخدم
        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        # حذف التقرير
        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")

        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500
# وظائف مساعدة
def analyze_pdf_content(text):
    """تحليل محتوى PDF لاكتشاف التهديدات"""
    threats = []

    # اكتشاف JavaScript خطير
    js_patterns = [
        r'eval\(', r'exec\(', r'fromCharCode\(',
        r'document\.write\(', r'window\.open\(',
        r'javascript:', r'vbscript:'
    ]

    for pattern in js_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            threats.append({
                'type': 'JavaScript خطير',
                'description': f'تم اكتشاف {pattern} في المحتوى',
                'severity': 'high'
            })

    # اكتشاف روابط مشبوهة
    url_patterns = [
        r'http://[^\s]+', r'https://[^\s]+',
        r'www\.[^\s]+', r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    ]

    for pattern in url_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            if is_suspicious_url(match):
                threats.append({
                    'type': 'رابط مشبوه',
                    'description': f'رابط مشبوه: {match}',
                    'severity': 'medium'
                })

    return threats


def calculate_threat_score(api_results, threats):
    """حساب درجة التهديد"""
    score = 0

    # إضافة نقاط based on API results
    for result in api_results.values():
        if result.get('detected', False):
            score += 30

    # إضافة نقاط based on threats
    score += min(len(threats) * 10, 40)

    return min(score, 100)


def is_suspicious_url(url):
    """التحقق إذا كان الرابط مشبوهاً"""
    suspicious_domains = [
        'free', 'download', 'virus', 'malware',
        'hack', 'crack', 'keygen', 'torrent'
    ]

    return any(domain in url.lower() for domain in suspicious_domains)




############################################[ URL  analysis ]##############################################







from url_analyzer import analyze_url, setup_selenium  # إضافة هذا
from models import URLAnalysis  # إضافة هذا


# ... (بقية الكود)

@app.route('/URL_analysis', methods=['GET', 'POST'])
@login_required
def url_analysis():
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            flash('يجب إدخال رابط صحيح', 'danger')
            return redirect(url_for('url_analysis'))

        try:
            # استبدل بالمفتاح الخاص بك من VirusTotal
            VT_API_KEY = "4f6a1d5109c67e49c1b3e32acd3bf5c89fa500f9db8d759d3fadb2e9da67c94e"

            driver = setup_selenium()
            results = analyze_url(url, driver, vt_api_key=VT_API_KEY)
            driver.quit()

            if 'error' in results:
                flash(results['error'], 'danger')
                return redirect(url_for('url_analysis'))

            # حفظ النتائج في قاعدة البيانات
            url_analysis = URLAnalysis(
                url=url,
                is_malicious="مشبوه" in results['final_result'],
                ssl_status=results['ssl_status'],
                model_prediction=results['model_prediction'],
                content_analysis=results['content_analysis'],
                html_analysis=results['html_analysis'],
                javascript_analysis=results['javascript_analysis'],
                virustotal_result=results['virustotal_result'],
                final_result=results['final_result'],
                user_id=current_user.id
            )

            db.session.add(url_analysis)
            db.session.commit()

            return redirect(url_for('report_url_analysis', analysis_id=url_analysis.id))

        except Exception as e:
            flash(f'حدث خطأ أثناء تحليل الرابط: {str(e)}', 'danger')
            app.logger.error(f"خطأ في تحليل الرابط: {str(e)}")
            return redirect(url_for('url_analysis'))

    return render_template('URL_analysis.html')


@app.route('/report_url_analysis/<int:analysis_id>')
@login_required
def report_url_analysis(analysis_id):
    try:
        analysis = URLAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذا التقرير', 'danger')
            return redirect(url_for('dashboard'))

        return render_template('report_url_analysis.html', results=analysis.to_dict())
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'danger')
        app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
        return redirect(url_for('url_analysis'))


############################################[ EXE AND DLL analysis ]##############################################
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'sample' not in request.files:
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        file = request.files['sample']

        if file.filename == '':
            flash('لم يتم اختيار ملف', 'error')
            return redirect(request.url)

        if not allowed_file_exe(file.filename):
            flash('صيغة غير مدعومة، اختر ملف exe أو dll', 'error')
            return redirect(request.url)

        # استخدام ملف مؤقت بدلاً من الحفظ المباشر
        temp_dir = tempfile.gettempdir()
        temp_filename = f"malware_analysis_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.bin"
        file_path = os.path.join(temp_dir, temp_filename)

        try:
            file.save(file_path)
        except Exception as e:
            flash(f'خطأ في حفظ الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في حفظ الملف: {str(e)}")
            return redirect(request.url)

        # حساب حجم الملف فوراً قبل أي عمليات أخرى
        try:
            file_size = os.path.getsize(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في قراءة الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في قراءة الملف: {str(e)}")
            return redirect(request.url)

        filename = secure_filename(file.filename)

        try:
            file_hash = calculate_file_hash(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في حساب بصمة الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في حساب بصمة الملف: {str(e)}")
            return redirect(request.url)

        # التحقق مما إذا كانت العينة محللة سابقاً
        existing_sample = AnalysisSample.query.filter_by(file_hash=file_hash).first()
        if existing_sample:
            safe_delete(file_path)
            flash('تم تحليل هذه العينة سابقاً', 'info')
            return redirect(url_for('sample_detail', sample_id=existing_sample.id))

        # استخراج الميزات
        try:
            header_info, sections_info, imports_info, dynamic_indicators = extract_pe_features(file_path)
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في استخراج ميزات الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في استخراج ميزات الملف: {str(e)}")
            return redirect(request.url)

        # التصنيف باستخدام نموذج ML
        try:
            pred, proba = predict_sample(file_path)
            is_malicious = pred == 1
        except Exception as e:
            safe_delete(file_path)
            flash(f'خطأ في تحليل الملف: {str(e)}', 'error')
            app.logger.error(f"خطأ في تحليل الملف: {str(e)}")
            return redirect(request.url)

        # التحليلات الجديدة
        strings = extract_strings(file_path)
        binwalk_results = run_binwalk(file_path)
        entropy = analyze_entropy(file_path)
        packed, _ = detect_packing(file_path)
        network_indicators = analyze_network_indicators(strings)
        yara_matches = apply_yara_rules(file_path)
        libraries = extract_libraries(file_path)
        powershell_commands = extract_powershell_commands(strings)
        persistence_indicators = analyze_persistence_mechanisms(strings)
        c2_indicators = detect_c2_servers(
            network_indicators['domains'],
            network_indicators['ips']
        )
        mitre_techniques = mitre_attck_mapping(
            strings +
            [match['rule'] for match in yara_matches] +
            persistence_indicators
        )

        sandbox_report = {}
        if Config.DYNAMIC_ANALYSIS_ENABLED:
            sandbox = Sandbox(file_path)
            sandbox_report = sandbox.run()

        # حذف الملف المؤقت بعد الانتهاء من التحليل
        if not safe_delete(file_path):
            app.logger.warning(f"تعذر حذف الملف المؤقت: {file_path}")

        # إصلاح: تطبيق معالجة خاصة على البيانات قبل التخزين
        libraries = fix_stored_data(libraries)
        powershell_commands = fix_stored_data(powershell_commands)
        persistence_indicators = fix_stored_data(persistence_indicators)
        c2_indicators = fix_stored_data(c2_indicators)

        # حفظ العينة في قاعدة البيانات
        try:
            sample = AnalysisSample(
                filename=filename,
                file_size=file_size,
                file_hash=file_hash,
                prediction='خبيث' if is_malicious else 'آمن',
                probability=proba,
                is_malicious=is_malicious,
                user_id=current_user.id if current_user.is_authenticated else None,
                header_info=json.dumps(header_info),
                sections_info=json.dumps(sections_info),
                imports_info=json.dumps(imports_info),
                dynamic_indicators=json.dumps(dynamic_indicators),
                strings=json.dumps(strings),
                binwalk_results=json.dumps(binwalk_results),
                entropy=entropy,
                packed=packed,
                network_indicators=json.dumps(network_indicators),
                yara_matches=json.dumps([match['rule'] for match in yara_matches]),
                libraries=json.dumps(libraries),
                powershell_commands=json.dumps(powershell_commands),
                persistence_indicators=json.dumps(persistence_indicators),
                c2_indicators=json.dumps(c2_indicators),
                mitre_techniques=json.dumps(mitre_techniques)
            )

            db.session.add(sample)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'خطأ في حفظ نتائج التحليل: {str(e)}', 'error')
            app.logger.error(f"خطأ في حفظ نتائج التحليل: {str(e)}")
            return redirect(request.url)

        return redirect(url_for('sample_detail', sample_id=sample.id))

    return render_template('index.html')


@app.route('/sample/<int:sample_id>')
def sample_detail(sample_id):
    try:
        sample = AnalysisSample.query.get_or_404(sample_id)

        # إصلاح: معالجة البيانات المخزنة قبل العرض
        def fix_data(data):
            if isinstance(data, list):
                if all(isinstance(item, list) for item in data):
                    return [''.join(item) for item in data]
            return data

        # تحويل البيانات من JSON إلى كائنات Python
        header_info = json.loads(sample.header_info) if sample.header_info else {}
        sections_info = json.loads(sample.sections_info) if sample.sections_info else []
        imports_info = json.loads(sample.imports_info) if sample.imports_info else {}
        dynamic_indicators = json.loads(sample.dynamic_indicators) if sample.dynamic_indicators else {}
        strings = json.loads(sample.strings) if sample.strings else {}
        binwalk_results = json.loads(sample.binwalk_results) if sample.binwalk_results else []
        network_indicators = json.loads(sample.network_indicators) if sample.network_indicators else {}
        yara_matches = json.loads(sample.yara_matches) if sample.yara_matches else []
        libraries = json.loads(sample.libraries) if sample.libraries else []
        powershell_commands = json.loads(sample.powershell_commands) if sample.powershell_commands else []
        persistence_indicators = json.loads(sample.persistence_indicators) if sample.persistence_indicators else []
        c2_indicators = json.loads(sample.c2_indicators) if sample.c2_indicators else []
        mitre_techniques = json.loads(sample.mitre_techniques) if sample.mitre_techniques else []

        # إصلاح: معالجة المكتبات والأوامر
        libraries = fix_data(libraries)
        powershell_commands = fix_data(powershell_commands)
        persistence_indicators = fix_data(persistence_indicators)
        c2_indicators = fix_data(c2_indicators)

        # إضافة متغير sandbox_report فارغ لتجنب الأخطاء في القالب
        sandbox_report = {}

        return render_template(
            'report.html',
            sample=sample,
            strings=strings,
            header_info=header_info,
            sections_info=sections_info,
            imports_info=imports_info,
            dynamic_indicators=dynamic_indicators,
            sandbox_report=sandbox_report,
            binwalk_results=binwalk_results,
            entropy=sample.entropy,
            packed=sample.packed,
            network_indicators=network_indicators,
            yara_matches=yara_matches,
            libraries=libraries,
            powershell_commands=powershell_commands,
            persistence_indicators=persistence_indicators,
            c2_indicators=c2_indicators,
            mitre_techniques=mitre_techniques
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل التقرير: {str(e)}")
        return redirect(url_for('index'))


@app.route('/share/<token>')
def shared_report(token):
    try:
        sample = AnalysisSample.query.filter_by(share_token=token).first()
        if not sample:
            flash('رابط التقرير غير صالح أو منتهي الصلاحية', 'error')
            return redirect(url_for('index'))

        if sample.share_expiry and sample.share_expiry < datetime.utcnow():
            flash('انتهت صلاحية رابط التقرير', 'error')
            return redirect(url_for('index'))

        # إصلاح: معالجة البيانات المخزنة قبل العرض
        def fix_data(data):
            if isinstance(data, list):
                if all(isinstance(item, list) for item in data):
                    return [''.join(item) for item in data]
            return data

        # تحويل البيانات من JSON إلى كائنات Python
        header_info = json.loads(sample.header_info) if sample.header_info else {}
        sections_info = json.loads(sample.sections_info) if sample.sections_info else []
        imports_info = json.loads(sample.imports_info) if sample.imports_info else {}
        dynamic_indicators = json.loads(sample.dynamic_indicators) if sample.dynamic_indicators else {}
        strings = json.loads(sample.strings) if sample.strings else []
        binwalk_results = json.loads(sample.binwalk_results) if sample.binwalk_results else []
        network_indicators = json.loads(sample.network_indicators) if sample.network_indicators else {}
        yara_matches = json.loads(sample.yara_matches) if sample.yara_matches else []
        libraries = json.loads(sample.libraries) if sample.libraries else []
        powershell_commands = json.loads(sample.powershell_commands) if sample.powershell_commands else []
        persistence_indicators = json.loads(sample.persistence_indicators) if sample.persistence_indicators else []
        c2_indicators = json.loads(sample.c2_indicators) if sample.c2_indicators else []
        mitre_techniques = json.loads(sample.mitre_techniques) if sample.mitre_techniques else []

        # إصلاح: معالجة المكتبات والأوامر
        libraries = fix_data(libraries)
        powershell_commands = fix_data(powershell_commands)
        persistence_indicators = fix_data(persistence_indicators)
        c2_indicators = fix_data(c2_indicators)

        # إضافة متغير sandbox_report فارغ لتجنب الأخطاء في القالب
        sandbox_report = {}

        return render_template(
            'shared_report.html',
            sample=sample,
            header_info=header_info,
            sections_info=sections_info,
            imports_info=imports_info,
            dynamic_indicators=dynamic_indicators,
            sandbox_report=sandbox_report,
            strings=strings,
            binwalk_results=binwalk_results,
            entropy=sample.entropy,
            packed=sample.packed,
            network_indicators=network_indicators,
            yara_matches=yara_matches,
            libraries=libraries,
            powershell_commands=powershell_commands,
            persistence_indicators=persistence_indicators,
            c2_indicators=c2_indicators,
            mitre_techniques=mitre_techniques
        )
    except Exception as e:
        flash(f'خطأ في تحميل التقرير المشترك: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل التقرير المشترك: {str(e)}")
        return redirect(url_for('index'))


@app.route('/generate_pdf/<int:sample_id>')
@login_required
def generate_pdf(sample_id):
    try:
        sample = AnalysisSample.query.get_or_404(sample_id)

        # إصلاح: معالجة البيانات المخزنة قبل العرض
        def fix_data(data):
            if isinstance(data, list):
                if all(isinstance(item, list) for item in data):
                    return [''.join(item) for item in data]
            return data

        # تحويل البيانات من JSON إلى كائنات Python
        header_info = json.loads(sample.header_info) if sample.header_info else {}
        sections_info = json.loads(sample.sections_info) if sample.sections_info else []
        imports_info = json.loads(sample.imports_info) if sample.imports_info else {}
        dynamic_indicators = json.loads(sample.dynamic_indicators) if sample.dynamic_indicators else {}
        strings = json.loads(sample.strings) if sample.strings else {}
        binwalk_results = json.loads(sample.binwalk_results) if sample.binwalk_results else []
        network_indicators = json.loads(sample.network_indicators) if sample.network_indicators else {}
        yara_matches = json.loads(sample.yara_matches) if sample.yara_matches else []
        libraries = json.loads(sample.libraries) if sample.libraries else []
        powershell_commands = json.loads(sample.powershell_commands) if sample.powershell_commands else []
        persistence_indicators = json.loads(sample.persistence_indicators) if sample.persistence_indicators else []
        c2_indicators = json.loads(sample.c2_indicators) if sample.c2_indicators else []
        mitre_techniques = json.loads(sample.mitre_techniques) if sample.mitre_techniques else []

        # إصلاح: معالجة المكتبات والأوامر
        libraries = fix_data(libraries)
        powershell_commands = fix_data(powershell_commands)
        persistence_indicators = fix_data(persistence_indicators)
        c2_indicators = fix_data(c2_indicators)

        # إضافة متغير sandbox_report فارغ لتجنب الأخطاء في القالب
        sandbox_report = {}

        # توليد محتوى HTML للتقرير
        html_content = render_template(
            'report.html',
            sample=sample,
            header_info=header_info,
            sections_info=sections_info,
            imports_info=imports_info,
            dynamic_indicators=dynamic_indicators,
            sandbox_report=sandbox_report,
            strings=strings,
            binwalk_results=binwalk_results,
            entropy=sample.entropy,
            packed=sample.packed,
            network_indicators=network_indicators,
            yara_matches=yara_matches,
            libraries=libraries,
            powershell_commands=powershell_commands,
            persistence_indicators=persistence_indicators,
            c2_indicators=c2_indicators,
            mitre_techniques=mitre_techniques,
            pdf_mode=True
        )

        # توليد ملف PDF
        pdf_filename = f"report_{sample.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
        pdf_path = generate_pdf_report(html_content, pdf_filename)

        if pdf_path:
            # حذف ملف PDF بعد إرساله
            try:
                return send_file(
                    pdf_path,
                    as_attachment=True,
                    download_name=f"تقرير_تحليل_{sample.filename}.pdf",
                    on_close=lambda: safe_delete(pdf_path)
                )
            except Exception as e:
                flash(f'خطأ في إرسال ملف PDF: {str(e)}', 'error')
                app.logger.error(f"خطأ في إرسال ملف PDF: {str(e)}")
                safe_delete(pdf_path)
                return redirect(url_for('sample_detail', sample_id=sample_id))
        else:
            flash('فشل في توليد ملف PDF', 'error')
            return redirect(url_for('sample_detail', sample_id=sample_id))
    except Exception as e:
        flash(f'خطأ في توليد ملف PDF: {str(e)}', 'error')
        app.logger.error(f"خطأ في توليد ملف PDF: {str(e)}")
        return redirect(url_for('sample_detail', sample_id=sample_id))


@app.route('/share_sample/<int:sample_id>', methods=['POST'])
@login_required
def share_sample(sample_id):
    try:
        expiry_days = int(request.form.get('expiry_days', 7))
        token = create_share_link(sample_id, expiry_days)

        if token:
            share_url = url_for('shared_report', token=token, _external=True)
            return jsonify({
                'success': True,
                'share_url': share_url,
                'expiry': (datetime.utcnow() + timedelta(days=expiry_days)).strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({'success': False, 'message': 'العينة غير موجودة'})
    except Exception as e:
        app.logger.error(f"خطأ في مشاركة العينة: {str(e)}")
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'})


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # إحصائيات تحليل البرمجيات الخبيثة للمستخدم الحالي
        user_samples = AnalysisSample.query.filter_by(user_id=current_user.id)
        total_samples = user_samples.count()
        malicious_samples = user_samples.filter_by(is_malicious=True).count()
        benign_samples = total_samples - malicious_samples
        latest_samples = user_samples.order_by(AnalysisSample.upload_date.desc()).limit(10).all()

        # إحصائيات تحليلات أمن الويب للمستخدم الحالي
        user_web_analyses = WebAnalysis.query.filter_by(user_id=current_user.id)
        web_analyses_count = user_web_analyses.count()
        safe_domains = user_web_analyses.filter(WebAnalysis.vulnerable_links == 0).count()
        vulnerabilities_count = db.session.query(
            db.func.sum(WebAnalysis.vulnerable_links)
        ).filter(WebAnalysis.user_id == current_user.id).scalar() or 0
        vulnerable_domains = user_web_analyses.filter(WebAnalysis.vulnerable_links > 0).count()
        latest_web_analyses = user_web_analyses.order_by(WebAnalysis.scan_date.desc()).limit(10).all()

        # إحصائيات تحليلات الروابط للمستخدم الحالي
        user_url_analyses = URLAnalysis.query.filter_by(user_id=current_user.id)
        url_analyses_count = user_url_analyses.count()
        malicious_urls = user_url_analyses.filter_by(is_malicious=True).count()
        safe_urls = url_analyses_count - malicious_urls
        latest_url_analyses = user_url_analyses.order_by(URLAnalysis.scan_date.desc()).limit(10).all()

        # إحصائيات تحليل الكود للمستخدم الحالي
        user_code_analyses = CodeAnalysis.query.filter_by(user_id=current_user.id)
        code_analyses_count = user_code_analyses.count()
        vulnerable_code = user_code_analyses.filter(CodeAnalysis.vulnerabilities != '[]').count()
        secure_code = code_analyses_count - vulnerable_code
        latest_code_analyses = user_code_analyses.order_by(CodeAnalysis.analysis_date.desc()).limit(10).all()

        # إحصائيات PDF
        user_pdf_analyses = PDFAnalysis.query.filter_by(user_id=current_user.id)
        pdf_analyses_count = user_pdf_analyses.count()
        malicious_pdfs = user_pdf_analyses.filter_by(is_malicious=True).count()
        safe_pdfs = pdf_analyses_count - malicious_pdfs
        latest_pdf_analyses = user_pdf_analyses.order_by(PDFAnalysis.upload_date.desc()).limit(5).all()
        # إحصائيات تحليلات الصور
        user_image_analyses = ImageAnalysis.query.filter_by(user_id=current_user.id)
        image_analyses_count = user_image_analyses.count()
        malicious_images = user_image_analyses.filter_by(is_malicious=True).count()
        safe_images = image_analyses_count - malicious_images
        latest_image_analyses = user_image_analyses.order_by(ImageAnalysis.upload_date.desc()).limit(10).all()

        return render_template(
            'dashboard.html',
            # بيانات البرمجيات الخبيثة
            total_samples=total_samples,
            malicious_samples=malicious_samples,
            benign_samples=benign_samples,
            latest_samples=latest_samples,

            # بيانات أمن الويب
            web_analyses_count=web_analyses_count,
            safe_domains=safe_domains,
            vulnerabilities_count=vulnerabilities_count,
            web_analyses=latest_web_analyses,
            vulnerable_domains=vulnerable_domains,

            # بيانات تحليل الروابط
            url_analyses_count=url_analyses_count,
            malicious_urls=malicious_urls,
            safe_urls=safe_urls,
            url_analyses=latest_url_analyses,

            # بيانات تحليل الكود
            code_analyses_count=code_analyses_count,
            vulnerable_code=vulnerable_code,
            secure_code=secure_code,
            code_analyses=latest_code_analyses,
            # إحصائيات PDF الجديدة
            pdf_analyses_count=pdf_analyses_count,
            malicious_pdfs=malicious_pdfs,
            safe_pdfs=safe_pdfs,
            latest_pdf_analyses=latest_pdf_analyses,
            # إحصائيات الصور الجديدة
            image_analyses_count=image_analyses_count,
            malicious_images=malicious_images,
            safe_images=safe_images,
            latest_image_analyses=latest_image_analyses


        )
    except Exception as e:
        flash(f'خطأ في تحميل لوحة التحكم: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل لوحة التحكم: {str(e)}")
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'خطأ في تسجيل الخروج: {str(e)}', 'error')
        app.logger.error(f"خطأ في تسجيل الخروج: {str(e)}")
        return redirect(url_for('index'))
@app.route('/contact')
def contact():
    return render_template('contact.html')

import os
from werkzeug.utils import secure_filename
from flask import request, jsonify, flash, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from forms import ProfileForm, PasswordForm, SettingsForm

# الإعدادات
UPLOAD_FOLDER = 'static/uploads/profiles'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/settings')
@login_required
def settings():
    profile_form = ProfileForm()
    password_form = PasswordForm()
    settings_form = SettingsForm()

    # تعبئة النماذج ببيانات المستخدم الحالية
    profile_form.username.data = current_user.username
    profile_form.email.data = current_user.email

    # تحميل الإعدادات المحفوظة إذا وجدت
    user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if user_settings:
        settings_form.language.data = user_settings.language
        settings_form.time_format.data = user_settings.time_format
        settings_form.email_notifications.data = user_settings.email_notifications
        settings_form.security_notifications.data = user_settings.security_notifications
        settings_form.app_notifications.data = user_settings.app_notifications
        settings_form.newsletter.data = user_settings.newsletter
        settings_form.private_account.data = user_settings.private_account
        settings_form.secure_login.data = user_settings.secure_login
        settings_form.analytics.data = user_settings.analytics

    return render_template('settings.html',
                           profile_form=profile_form,
                           password_form=password_form,
                           settings_form=settings_form)


@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        username = request.form.get('username')
        email = request.form.get('email')

        if not all([username, email]):
            return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'})

        # التحقق من أن البريد الإلكتروني فريد (إذا تم تغييره)
        if email != current_user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'message': 'البريد الإلكتروني مستخدم بالفعل'})

        # التحقق من أن اسم المستخدم فريد (إذا تم تغييره)
        if username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'message': 'اسم المستخدم مستخدم بالفعل'})

        # تحديث بيانات المستخدم
        current_user.username = username
        current_user.email = email

        # معالجة رفع الصورة إذا وجدت
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename != '' and allowed_file(file.filename):
                if file.content_length > MAX_FILE_SIZE:
                    return jsonify({'success': False, 'message': 'حجم الملف يجب أن يكون أقل من 2MB'})

                # إنشاء مجلد التحميل إذا لم يكن موجوداً
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)

                # إنشاء اسم ملف فريد
                filename = secure_filename(
                    f"{current_user.id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                filepath = os.path.join(UPLOAD_FOLDER, filename)

                # حفظ الملف
                file.save(filepath)

                # حذف الصورة القديمة إذا كانت موجودة
                if current_user.profile_image and os.path.exists(
                        os.path.join(UPLOAD_FOLDER, current_user.profile_image)):
                    os.remove(os.path.join(UPLOAD_FOLDER, current_user.profile_image))

                current_user.profile_image = filename

        db.session.commit()

        return jsonify({'success': True, 'message': 'تم تحديث الملف الشخصي بنجاح'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تحديث الملف الشخصي'})


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'})

        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'كلمة المرور غير متطابقة'})

        if not check_password_hash(current_user.password, current_password):
            return jsonify({'success': False, 'message': 'كلمة المرور الحالية غير صحيحة'})

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({'success': True, 'message': 'تم تغيير كلمة المرور بنجاح'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تغيير كلمة المرور'})


@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    try:
        # استقبال البيانات من النموذج
        language = request.form.get('language')
        time_format = request.form.get('time_format')
        email_notifications = request.form.get('email_notifications') == 'on'
        security_notifications = request.form.get('security_notifications') == 'on'
        app_notifications = request.form.get('app_notifications') == 'on'
        newsletter = request.form.get('newsletter') == 'on'
        private_account = request.form.get('private_account') == 'on'
        secure_login = request.form.get('secure_login') == 'on'
        analytics = request.form.get('analytics') == 'on'

        # البحث عن إعدادات المستخدم أو إنشاؤها إذا لم تكن موجودة
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if not user_settings:
            user_settings = UserSettings(user_id=current_user.id)
            db.session.add(user_settings)

        # تحديث الإعدادات
        user_settings.language = language
        user_settings.time_format = time_format
        user_settings.email_notifications = email_notifications
        user_settings.security_notifications = security_notifications
        user_settings.app_notifications = app_notifications
        user_settings.newsletter = newsletter
        user_settings.private_account = private_account
        user_settings.secure_login = secure_login
        user_settings.analytics = analytics

        db.session.commit()

        return jsonify({'success': True, 'message': 'تم تحديث الإعدادات بنجاح'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تحديث الإعدادات'})







@app.errorhandler(413)
def request_entity_too_large(error):
    max_size_mb = app.config['MAX_FILE_SIZE'] // (1024 * 1024)
    flash(f'حجم الملف كبير جداً، الحد الأقصى {max_size_mb}MB', 'error')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"خطأ في الخادم: {str(error)}")
    return render_template('500.html'), 500


@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"حدث خطأ غير متوقع: {str(e)}")
    # صفحة خطأ احتياطية في حالة عدم وجود قالب error.html
    error_html = f"""
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>خطأ في النظام</title>
        <style>
            body {{ font-family: Tahoma; text-align: center; padding: 50px; }}
            h1 {{ color: #d9534f; }}
            .error-details {{ 
                background: #f8d7da; 
                border: 1px solid #f5c6cb; 
                padding: 20px; 
                margin: 20px auto; 
                max-width: 800px;
                text-align: right;
            }}
        </style>
    </head>
    <body>
        <h1>⚠️ حدث خطأ غير متوقع</h1>
        <p>نعتذر عن الإزعاج، يرجى المحاولة مرة أخرى لاحقاً</p>

        <div class="error-details">
            <strong>تفاصيل الخطأ:</strong><br>
            {str(e)}
        </div>

        <p>
            <a href="{url_for('index')}" style="color: #004085;">العودة للصفحة الرئيسية</a>
        </p>
    </body>
    </html>
    """

    return error_html, 500

from sqlalchemy import func
from datetime import datetime, timedelta
from flask import render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from sqlalchemy import func
from models import User, AnalysisSample, WebAnalysis, URLAnalysis, PDFAnalysis, CodeAnalysis


# ... (بقية الاستيرادات والتكوين)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)

    try:
        # إحصائيات المستخدمين
        total_users = User.query.count()
        active_users = User.query.filter(User.last_login >= (datetime.utcnow() - timedelta(days=7))).count()
        admin_users = User.query.filter_by(is_admin=True).count()

        # إحصائيات العينات
        total_samples = AnalysisSample.query.count()
        malicious_samples = AnalysisSample.query.filter_by(is_malicious=True).count()
        benign_samples = total_samples - malicious_samples

        # إحصائيات تحليلات الويب
        web_analyses_count = WebAnalysis.query.count()
        vulnerable_domains = WebAnalysis.query.filter(WebAnalysis.vulnerable_links > 0).count()

        # إحصائيات تحليلات الروابط
        url_analyses_count = URLAnalysis.query.count()
        malicious_urls = URLAnalysis.query.filter_by(is_malicious=True).count()

        # إحصائيات تحليلات PDF
        total_pdf_analyses = PDFAnalysis.query.count()
        malicious_pdfs = PDFAnalysis.query.filter_by(is_malicious=True).count()
        safe_pdfs = total_pdf_analyses - malicious_pdfs

        # حساب النسب المئوية لتحليلات PDF
        safe_pdfs_percentage = round((safe_pdfs / total_pdf_analyses * 100), 2) if total_pdf_analyses > 0 else 0
        malicious_pdfs_percentage = round((malicious_pdfs / total_pdf_analyses * 100),
                                          2) if total_pdf_analyses > 0 else 0

        # تحليلات PDF اليوم
        today = datetime.utcnow().date()
        pdf_analyses_today = PDFAnalysis.query.filter(func.date(PDFAnalysis.scan_date) == today).count()

        # إحصائيات تحليلات الكود
        code_analyses_count = CodeAnalysis.query.count()
        code_analyses_today = CodeAnalysis.query.filter(func.date(CodeAnalysis.analysis_date) == today).count()

        # التحليلات اليومية الأخرى
        file_analyses_today = AnalysisSample.query.filter(func.date(AnalysisSample.upload_date) == today).count()
        web_analyses_today = WebAnalysis.query.filter(func.date(WebAnalysis.scan_date) == today).count()
        url_analyses_today = URLAnalysis.query.filter(func.date(URLAnalysis.scan_date) == today).count()

        # إحصائيات المستخدمين والتحليلات
        all_users = User.query.all()
        users_stats = []
        for user in all_users:
            file_analyses = AnalysisSample.query.filter_by(user_id=user.id).count()
            web_analyses = WebAnalysis.query.filter_by(user_id=user.id).count()
            url_analyses = URLAnalysis.query.filter_by(user_id=user.id).count()
            code_analyses = CodeAnalysis.query.filter_by(user_id=user.id).count()
            pdf_analyses = PDFAnalysis.query.filter_by(user_id=user.id).count()

            total_analyses = file_analyses + web_analyses + url_analyses + code_analyses + pdf_analyses

            users_stats.append({
                'username': user.username,
                'is_admin': user.is_admin,
                'file_analyses': file_analyses,
                'web_analyses': web_analyses,
                'url_analyses': url_analyses,
                'code_analyses': code_analyses,
                'pdf_analyses': pdf_analyses,
                'total_analyses': total_analyses
            })

        # آخر المستخدمين المسجلين
        latest_users = User.query.order_by(User.created_at.desc()).limit(5).all()

        # أحدث العينات المفحوصة
        latest_samples = AnalysisSample.query.order_by(AnalysisSample.upload_date.desc()).limit(5).all()

        # أحدث تحليلات الويب
        latest_web_analyses = WebAnalysis.query.order_by(WebAnalysis.scan_date.desc()).limit(5).all()

        # أحدث تحليلات الروابط
        latest_url_analyses = URLAnalysis.query.order_by(URLAnalysis.scan_date.desc()).limit(5).all()

        # أحدث تحليلات PDF
        latest_pdf_analyses = PDFAnalysis.query.order_by(PDFAnalysis.scan_date.desc()).limit(5).all()

        # أحدث تحليلات الكود
        latest_code_analyses = CodeAnalysis.query.order_by(CodeAnalysis.analysis_date.desc()).limit(5).all()

        return render_template(
            'admin_dashboard.html',
            # إحصائيات المستخدمين
            total_users=total_users,
            active_users=active_users,
            admin_users=admin_users,

            # إحصائيات العينات
            total_samples=total_samples,
            malicious_samples=malicious_samples,
            benign_samples=benign_samples,

            # إحصائيات الويب
            web_analyses_count=web_analyses_count,
            vulnerable_domains=vulnerable_domains,

            # إحصائيات الروابط
            url_analyses_count=url_analyses_count,
            malicious_urls=malicious_urls,

            # إحصائيات PDF
            total_pdf_analyses=total_pdf_analyses,
            malicious_pdfs=malicious_pdfs,
            safe_pdfs=safe_pdfs,
            safe_pdfs_percentage=safe_pdfs_percentage,
            malicious_pdfs_percentage=malicious_pdfs_percentage,
            pdf_analyses_today=pdf_analyses_today,

            # إحصائيات الكود
            code_analyses_count=code_analyses_count,
            code_analyses_today=code_analyses_today,

            # التحليلات اليومية
            file_analyses_today=file_analyses_today,
            web_analyses_today=web_analyses_today,
            url_analyses_today=url_analyses_today,

            # إحصائيات المستخدمين والتحليلات
            users_stats=users_stats,
            all_users=all_users,

            # القوائم
            latest_users=latest_users,
            latest_samples=latest_samples,
            latest_web_analyses=latest_web_analyses,
            latest_url_analyses=latest_url_analyses,
            latest_pdf_analyses=latest_pdf_analyses,
            code_analyses=latest_code_analyses
        )
    except Exception as e:
        flash(f'خطأ في تحميل لوحة التحكم: {str(e)}', 'error')
        app.logger.error(f"خطأ في تحميل لوحة التحكم: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)

    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('لا يمكن حذف حسابك الخاص!', 'danger')
        return redirect(url_for('admin_users'))

    try:
        # حذف جميع بيانات المستخدم
        AnalysisSample.query.filter_by(user_id=user_id).delete()
        WebAnalysis.query.filter_by(user_id=user_id).delete()
        URLAnalysis.query.filter_by(user_id=user_id).delete()

        db.session.delete(user)
        db.session.commit()
        flash('تم حذف المستخدم بنجاح', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء حذف المستخدم: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('لا يمكن تعديل صلاحيات حسابك الخاص!', 'danger')
        return redirect(url_for('admin_users'))

    try:
        user.is_admin = not user.is_admin
        db.session.commit()
        status = "مسؤول" if user.is_admin else "مستخدم عادي"
        flash(f'تم تغيير صلاحية المستخدم إلى {status}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'حدث خطأ أثناء تعديل الصلاحيات: {str(e)}', 'danger')

    return redirect(url_for('admin_users'))

model = joblib.load("models_web_c_a/security_model.pkl")
vectorizer = joblib.load("models_web_c_a/vectorizer.pkl")


@app.route('/web_code_analysis', methods=['GET', 'POST'])
@login_required  # إذا كان التطبيق يتطلب تسجيل دخول
def web_code_analysis():
    result = None
    code = ""
    url_error = None
    selected_input_type = "code"
    analysis_id = None

    if request.method == 'POST':
        input_type = request.form.get('input_type', 'code')
        selected_input_type = input_type
        uploaded_file = request.files.get('file')

        if input_type == 'code':
            code = request.form.get('code', '')

        elif input_type == 'url':
            url = request.form.get('url', '')
            if not url:
                url_error = "يرجى إدخال رابط صحيح."
            else:
                try:
                    response = requests.get(url, timeout=7, verify=False)
                    response.raise_for_status()
                    code = response.text
                except Exception as e:
                    url_error = f"فشل في جلب المحتوى من الرابط: {str(e)}"

        elif input_type == 'file' and uploaded_file and uploaded_file.filename != '':
            try:
                code = uploaded_file.read().decode(errors='ignore')
            except Exception as e:
                url_error = f"خطأ في قراءة الملف: {str(e)}"

        if code and not url_error:
            try:
                vectorized_code = vectorizer.transform([code])
                prediction_proba = model.predict_proba(vectorized_code)[0]
                labels = model.classes_

                predictions = {label: round(prob * 100, 2) for label, prob in zip(labels, prediction_proba)}
                sorted_probs = dict(sorted(predictions.items(), key=lambda item: item[1], reverse=True))

                result = {
                    "predictions": sorted_probs,
                    "total_flags": len([v for v in sorted_probs.values() if v > 30]),
                    "confidence": max(predictions.values()) if predictions else 0,
                }

                # تحليل الكود لاكتشاف الثغرات الشائعة
                vulnerabilities = detect_vulnerabilities(code)

                # حفظ التحليل في قاعدة البيانات
                code_analysis = CodeAnalysis(
                    analysis_type=input_type,
                    content=code,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                code_analysis.set_model_predictions(result)
                code_analysis.set_vulnerabilities(vulnerabilities)

                db.session.add(code_analysis)
                db.session.commit()
                analysis_id = code_analysis.id

                # Redirect to report page with data
                return redirect(url_for('report_web_code_analysis', analysis_id=analysis_id))

            except Exception as e:
                flash(f"خطأ في التنبؤ: {str(e)}", 'error')

    return render_template("web_code_analysis.html",
                           code=code,
                           url_error=url_error,
                           selected_input_type=selected_input_type)


def detect_vulnerabilities(code):
    """اكتشاف الثغرات الأمنية في الكود"""
    vulnerabilities = []

    # اكتشاف حقن SQL
    sql_patterns = [r"SELECT\s.*?\sFROM", r"INSERT\sINTO", r"UPDATE\s.*?\sSET", r"DELETE\sFROM"]
    if any(re.search(pattern, code, re.IGNORECASE) for pattern in sql_patterns):
        if not re.search(r"prepare\(", code, re.IGNORECASE):
            vulnerabilities.append({
                "name": "حقن SQL",
                "description": "تم اكتشاف استعلامات SQL مباشرة دون استخدام استعلامات معلمة",
                "severity": "عالي",
                "solution": "استخدام استعلامات معلمة (Prepared Statements) لمنع هجمات حقن SQL"
            })

    # اكتشاف XSS
    if re.search(r"echo\s*\$_GET|echo\s*\$_POST|echo\s*\$_REQUEST", code):
        if not re.search(r"htmlspecialchars\(", code):
            vulnerabilities.append({
                "name": "XSS (Cross-Site Scripting)",
                "description": "إخراج بيانات المستخدم دون تصفية",
                "severity": "متوسط",
                "solution": "استخدام htmlspecialchars() أو فلترة المدخلات قبل الإخراج"
            })

    # اكتشاف مشاكل جلسات
    if re.search(r"session_start\(", code) and not re.search(r"session_regenerate_id\(", code):
        vulnerabilities.append({
            "name": "تثبيت الجلسة",
            "description": "عدم تجديد معرف الجلسة بعد التسجيل",
            "severity": "متوسط",
            "solution": "استخدام session_regenerate_id(true) بعد تسجيل الدخول"
        })

    return vulnerabilities


# نقاط النهاية لحذف التقارير
@app.route('/delete_sample_report/<int:sample_id>', methods=['DELETE'])
@login_required
def delete_sample_report(sample_id):
    try:
        sample = AnalysisSample.query.get_or_404(sample_id)

        if sample.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(sample)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500


@app.route('/delete_web_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_web_report(analysis_id):
    try:
        analysis = WebAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500


@app.route('/delete_url_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_url_report(analysis_id):
    try:
        analysis = URLAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500


@app.route('/delete_code_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_code_report(analysis_id):
    try:
        analysis = CodeAnalysis.query.get_or_404(analysis_id)

        if analysis.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'غير مصرح لك بحذف هذا التقرير'
            }), 403

        db.session.delete(analysis)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'تم حذف التقرير بنجاح'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"خطأ في حذف التقرير: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'حدث خطأ أثناء حذف التقرير: {str(e)}'
        }), 500
@app.route('/report_web_code_analysis/<int:analysis_id>', methods=['GET', 'POST'])
def report_web_code_analysis(analysis_id):
    analysis = CodeAnalysis.query.get_or_404(analysis_id)
    code = analysis.content
    result = analysis.get_model_predictions()
    vulnerabilities = analysis.get_vulnerabilities()

    graphJSON = None
    if result and 'predictions' in result:
        labels = list(result['predictions'].keys())
        values = list(result['predictions'].values())

        fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
        fig.update_layout(
            title='توزيع الثغرات الأمنية',
            font=dict(family="Arial", size=12, color="#7f7f7f")
        )

        # الحل: استخدام plotly.io.to_json مباشرةً
        import plotly.io as pio
        graphJSON = pio.to_json(fig)  # ✅ الطريقة الصحيحة

    if request.method == 'POST' and 'generate_pdf' in request.form:
        return generate_pdf_report_code(code, result, vulnerabilities)
    return render_template(
        "report_web_code_analysis.html",
        code=code,
        result=result,
        vulnerabilities=vulnerabilities,
        graphJSON=graphJSON,
        analysis_id=analysis_id,
        analysis=analysis  # ✅ هذا هو المطلوب
    )


@app.route('/delete_image_report/<int:analysis_id>', methods=['DELETE'])
@login_required
def delete_image_report(analysis_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'غير مصرح به'}), 403

    try:
        analysis = ImageAnalysis.query.get_or_404(analysis_id)
        db.session.delete(analysis)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف التقرير بنجاح'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def generate_pdf_report_code(code, result, vulnerabilities):
    pdf = FPDF()
    pdf.add_page()

    # إضافة محتوى التقرير
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="تقرير تحليل الثغرات الأمنية", ln=True, align='C')
    pdf.ln(10)

    # إضافة معلومات الثغرات
    pdf.cell(200, 10, txt="الثغرات المكتشفة:", ln=True)
    for vuln in vulnerabilities:
        pdf.cell(200, 10, txt=f"- {vuln['name']} ({vuln['severity']})", ln=True)
        pdf.multi_cell(0, 10, txt=f"الوصف: {vuln['description']}")
        pdf.multi_cell(0, 10, txt=f"الحل: {vuln['solution']}")
        pdf.ln(5)

    # إضافة نتائج النموذج
    if result and 'predictions' in result:
        pdf.cell(200, 10, txt="نتائج تحليل النموذج:", ln=True)
        for vuln, prob in result['predictions'].items():
            pdf.cell(0, 10, f"- {vuln}: {prob}%", ln=True)

    # إرجاع ملف PDF
    pdf_output = BytesIO()
    pdf.output(pdf_output)
    pdf_output.seek(0)
    return send_file(pdf_output, download_name="security_report.pdf", as_attachment=True)
def fix_stored_data(data):
    """إصلاح البيانات المخزنة كمصفوفة أحرف"""
    if isinstance(data, list):
        if all(isinstance(item, list) for item in data):
            # إذا كانت القائمة تحتوي على قوائم (مصفوفات أحرف)
            return [''.join(item) for item in data]
        elif all(isinstance(item, str) for item in data):
            # إذا كانت القائمة تحتوي على سلاسل نصية
            return data
    return data



if __name__ == '__main__':

    # تشغيل التطبيق
    app.run(
        debug=app.config['DEBUG'],
        host=app.config['HOST'],
        port=app.config['PORT'])