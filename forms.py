from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class ProfileForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])

class PasswordForm(FlaskForm):
    current_password = PasswordField('كلمة المرور الحالية', validators=[DataRequired()])
    new_password = PasswordField('كلمة المرور الجديدة', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[DataRequired(), EqualTo('new_password')])

class SettingsForm(FlaskForm):
    language = SelectField('اللغة', choices=[('ar', 'العربية'), ('en', 'English'), ('fr', 'Français'), ('es', 'Español')])
    time_format = SelectField('الوحدة الزمنية', choices=[('24', '24 ساعة'), ('12', '12 ساعة (AM/PM)')])
    email_notifications = BooleanField('الإشعارات البريدية')
    security_notifications = BooleanField('إشعارات الأمان')
    app_notifications = BooleanField('إشعارات التطبيق')
    newsletter = BooleanField('النشرة الإخبارية')
    private_account = BooleanField('الحساب الخاص')
    secure_login = BooleanField('تسجيل الدخول الآمن')
    analytics = BooleanField('جمع بيانات التحليل')