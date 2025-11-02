from datetime import datetime
from flask_login import UserMixin
from database import db
import json


class User(UserMixin, db.Model):
    __tablename__ = 'users'  # تحديد اسم الجدول بشكل صريح

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=True)
    profile_image = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # العلاقات
    oauth = db.relationship('OAuth', back_populates='user', lazy=True)

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()


class OAuth(db.Model):
    __tablename__ = 'oauth'

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(256), nullable=False)
    token = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # تصحيح هنا
    user = db.relationship('User', back_populates='oauth')


class UserSettings(db.Model):
    __tablename__ = 'user_settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    language = db.Column(db.String(10), default='ar')
    time_format = db.Column(db.String(10), default='24')
    theme = db.Column(db.String(10), default='dark')
    email_notifications = db.Column(db.Boolean, default=True)
    security_notifications = db.Column(db.Boolean, default=True)
    app_notifications = db.Column(db.Boolean, default=True)
    newsletter = db.Column(db.Boolean, default=False)
    private_account = db.Column(db.Boolean, default=False)
    secure_login = db.Column(db.Boolean, default=True)
    analytics = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('settings', uselist=False))
class ImageAnalysis(db.Model):
    __tablename__ = 'image_analyses'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)


    # نتائج التحليل
    is_malicious = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Float, default=0.0)
    analysis_results = db.Column(db.Text)  # لتخزين النتائج بشكل JSON

    # نوع التهديد المكتشف
    threat_type = db.Column(db.String(100))  # مثل: "Phishing", "Malicious", "Injected", etc.

    user = db.relationship('User', backref=db.backref('image_analyses', lazy=True))

    def set_analysis_results(self, results_dict):
        """تحويل نتائج التحليل إلى JSON مع معالجة القيم المنطقية"""

        def convert_bools(obj):
            """دالة مساعدة لتحويل القيم المنطقية إلى نصوص"""
            if isinstance(obj, bool):
                return str(obj)
            elif isinstance(obj, dict):
                return {k: convert_bools(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_bools(item) for item in obj]
            return obj

        try:
            # تحويل القيم المنطقية إلى نصوص أولاً
            converted_dict = convert_bools(results_dict)
            self.analysis_results = json.dumps(converted_dict,
                                               ensure_ascii=False)  # تغيير هنا من self.results إلى self.analysis_results
        except Exception as e:
            # في حالة الخطأ، حفظ رسالة الخطأ بدلاً من ذلك
            self.analysis_results = json.dumps({"error": f"Failed to serialize results: {str(e)}"})  # وتغيير هنا أيضاً

    def get_analysis_results(self):
        if not self.analysis_results:
            return {}

        try:
            results = json.loads(self.analysis_results)

            # تحويل القيم النصية "True"/"False" إلى قيم منطقية
            def convert_str_bools(obj):
                if isinstance(obj, str):
                    if obj.lower() == 'true':
                        return True
                    elif obj.lower() == 'false':
                        return False
                elif isinstance(obj, dict):
                    return {k: convert_str_bools(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_str_bools(item) for item in obj]
                return obj

            return convert_str_bools(results)
        except json.JSONDecodeError as e:
            return {"error": f"Failed to parse analysis results: {str(e)}"}
class PDFAnalysis(db.Model):
    __tablename__ = 'pdf_analyses'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # تصحيح هنا
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text, nullable=False)
    is_malicious = db.Column(db.Boolean, default=False)
    threat_score = db.Column(db.Float, default=0.0)
    engines_used = db.Column(db.Text)
    engines_total = db.Column(db.Integer, default=0)
    engines_detected = db.Column(db.Integer, default=0)
    vulnerabilities = db.Column(db.Text)
    file_metadata = db.Column(db.Text)

    user = db.relationship('User', backref=db.backref('pdf_analyses', lazy=True))

    def set_results(self, results_dict):
        self.results = json.dumps(results_dict)

    def get_results(self):
        return json.loads(self.results) if self.results else {}

    def set_engines_used(self, engines_list):
        self.engines_used = json.dumps(engines_list)

    def get_engines_used(self):
        return json.loads(self.engines_used) if self.engines_used else []

    def set_vulnerabilities(self, vulnerabilities_list):
        self.vulnerabilities = json.dumps(vulnerabilities_list)

    def get_vulnerabilities(self):
        return json.loads(self.vulnerabilities) if self.vulnerabilities else []

    def set_file_metadata(self, metadata_dict):
        self.file_metadata = json.dumps(metadata_dict)

    def get_file_metadata(self):
        return json.loads(self.file_metadata) if self.file_metadata else {}


class CodeAnalysis(db.Model):
    __tablename__ = 'code_analyses'

    id = db.Column(db.Integer, primary_key=True)
    analysis_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerabilities = db.Column(db.Text)
    model_predictions = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا

    def set_vulnerabilities(self, vuln_list):
        self.vulnerabilities = json.dumps(vuln_list, ensure_ascii=False)

    def get_vulnerabilities(self):
        return json.loads(self.vulnerabilities) if self.vulnerabilities else []

    def set_model_predictions(self, predictions):
        self.model_predictions = json.dumps(predictions, ensure_ascii=False)

    def get_model_predictions(self):
        return json.loads(self.model_predictions) if self.model_predictions else {}


class URLAnalysis(db.Model):
    __tablename__ = 'url_analyses'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_malicious = db.Column(db.Boolean)
    ssl_status = db.Column(db.String(200))
    model_prediction = db.Column(db.String(50))
    content_analysis = db.Column(db.String(200))
    html_analysis = db.Column(db.String(200))
    javascript_analysis = db.Column(db.String(200))
    virustotal_result = db.Column(db.Text)
    final_result = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا

    def to_dict(self):
        return {
            "url": self.url,
            "ssl": {"status": "صالح" in self.ssl_status, "message": self.ssl_status},
            "model": {"prediction": -1 if "Phishing" in self.model_prediction else 1,
                      "label": self.model_prediction},
            "content": {"status": "لا توجد" in self.content_analysis,
                        "message": self.content_analysis},
            "html": {"status": "طبيعي" in self.html_analysis,
                     "message": self.html_analysis},
            "javascript": {"status": "لا توجد" in self.javascript_analysis,
                           "message": self.javascript_analysis},
            "vt": {"status": "آمن" in self.virustotal_result if self.virustotal_result else None,
                   "message": self.virustotal_result},
            "final": {"status": "آمن" in self.final_result,
                      "message": self.final_result}
        }


class WebAnalysis(db.Model):
    __tablename__ = 'web_analyses'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type = db.Column(db.String(50), nullable=False)
    total_links = db.Column(db.Integer)
    vulnerable_links = db.Column(db.Integer)
    vulnerabilities = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا
    user = db.relationship('User', backref=db.backref('web_analyses', lazy=True))

    def set_vulnerabilities(self, vuln_data):
        def convert_bools(obj):
            if isinstance(obj, bool):
                return str(obj)
            elif isinstance(obj, dict):
                return {k: convert_bools(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_bools(item) for item in obj]
            return obj

        try:
            self.vulnerabilities = json.dumps(convert_bools(vuln_data), ensure_ascii=False)
        except Exception as e:
            self.vulnerabilities = json.dumps({"error": str(e)})

    def get_vulnerabilities(self):
        return json.loads(self.vulnerabilities) if self.vulnerabilities else []


class AnalysisSample(db.Model):
    __tablename__ = 'analysis_samples'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    prediction = db.Column(db.String(50), nullable=False)
    probability = db.Column(db.Float, nullable=False)
    is_malicious = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # تصحيح هنا
    user = db.relationship('User', backref=db.backref('samples', lazy=True))

    # نتائج التحليل
    header_info = db.Column(db.Text)
    sections_info = db.Column(db.Text)
    imports_info = db.Column(db.Text)
    dynamic_indicators = db.Column(db.Text)
    sandbox_report = db.Column(db.Text)

    # الحقول الجديدة
    strings = db.Column(db.Text)
    binwalk_results = db.Column(db.Text)
    entropy = db.Column(db.Float)
    packed = db.Column(db.Boolean)
    network_indicators = db.Column(db.Text)
    yara_matches = db.Column(db.Text)
    libraries = db.Column(db.Text)
    powershell_commands = db.Column(db.Text)
    persistence_indicators = db.Column(db.Text)
    c2_indicators = db.Column(db.Text)
    mitre_techniques = db.Column(db.Text)

    # معلومات المشاركة
    share_token = db.Column(db.String(32), unique=True)
    share_expiry = db.Column(db.DateTime)

    # الحقول الأخرى
    network_activity = db.Column(db.Text)
    file_activity = db.Column(db.Text)
    process_tree = db.Column(db.Text)
    strings_info = db.Column(db.Text)

    def __repr__(self):
        return f'<AnalysisSample {self.filename}>'