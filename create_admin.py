import os
from app import app, db  # استيراد app و db من ملف app الرئيسي
from models import User
from werkzeug.security import generate_password_hash

# استخدم سياق التطبيق الموجود
with app.app_context():
    # إنشاء المستخدم الإداري
    admin = User(
        username='admin',
        email='admin@example.com',
        password=generate_password_hash('admin_password'),  # اختر كلمة مرور قوية
        is_admin=True,
        is_verified=True
    )

    # التحقق من عدم وجود مستخدم بنفس الاسم أو البريد
    existing_user = User.query.filter((User.username == 'admin') | (User.email == 'admin@example.com')).first()
    if existing_user:
        print("المستخدم موجود بالفعل!")
    else:
        # إضافة وحفظ في قاعدة البيانات
        db.session.add(admin)
        db.session.commit()
        print("تم إنشاء حساب المدير بنجاح!")