import os
import hashlib
import requests
from io import BytesIO
from PIL import Image, ImageEnhance, ImageFilter
import exifread
import pytesseract
from langdetect import detect, LangDetectException
import re
import filetype  # بديل عن python-magic


def calculate_file_hash(file_path, block_size=65536):
    """حساب الهاش للملف"""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            hasher.update(block)
    return hasher.hexdigest()


def get_file_type_info(file_path):
    """الحصول على معلومات نوع الملف باستخدام طرق متعددة"""
    file_info = {}

    try:
        # الطريقة 1: استخدام امتداد الملف
        import os
        _, ext = os.path.splitext(file_path)
        file_info['extension'] = ext.lower() if ext else 'no_extension'

        # الطريقة 2: استخدام filetype
        try:
            kind = filetype.guess(file_path)
            if kind:
                file_info['mime_type'] = kind.mime
                file_info['guessed_extension'] = kind.extension
                file_info['type_method'] = 'filetype'
        except Exception as e:
            file_info['filetype_error'] = str(e)

        # الطريقة 3: استخدام mimetypes المدمجة
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            file_info['mime_mimetypes'] = mime_type
            file_info['type_method'] = 'mimetypes'

        # إذا لم يتم التعرف على النوع، نستخدم البيانات الأولية
        if 'mime_type' not in file_info and 'mime_mimetypes' not in file_info:
            file_info['type_method'] = 'fallback'
            # محاولة تحديد النوع من المحتوى
            with open(file_path, 'rb') as f:
                header = f.read(100)  # قراءة أول 100 بايت
                if header.startswith(b'\xFF\xD8\xFF'):
                    file_info['mime_type'] = 'image/jpeg'
                elif header.startswith(b'\x89PNG\r\n\x1a\n'):
                    file_info['mime_type'] = 'image/png'
                elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
                    file_info['mime_type'] = 'image/gif'
                elif header.startswith(b'BM'):
                    file_info['mime_type'] = 'image/bmp'
                elif header.startswith(b'RIFF') and header[8:12] == b'WEBP':
                    file_info['mime_type'] = 'image/webp'
                else:
                    file_info['mime_type'] = 'application/octet-stream'

    except Exception as e:
        file_info['error'] = str(e)

    return file_info


def analyze_image_metadata(image_path):
    """تحليل البيانات الوصفية للصورة"""
    metadata = {}

    try:
        # استخدام filetype للكشف عن نوع الملف
        kind = filetype.guess(image_path)
        if kind:
            metadata['mime_type'] = kind.mime
            metadata['extension'] = kind.extension
        else:
            metadata['mime_type'] = 'unknown'
            metadata['extension'] = 'unknown'

        # تحليل EXIF data
        try:
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
                for tag, value in tags.items():
                    if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                        metadata[tag] = str(value)
        except Exception as exif_error:
            metadata['exif_error'] = str(exif_error)

        # تحليل أبعاد الصورة
        try:
            with Image.open(image_path) as img:
                metadata['dimensions'] = img.size
                metadata['format'] = img.format
                metadata['mode'] = img.mode
        except Exception as img_error:
            metadata['image_error'] = str(img_error)

    except Exception as e:
        metadata['error'] = str(e)

    return metadata


def check_hidden_data(image_path):
    """الكشف عن البيانات المخفية في الصورة"""
    hidden_data = {}

    try:
        # فحص وجود بيانات مخفية في نهاية الملف
        with open(image_path, 'rb') as f:
            content = f.read()
            # البحث عن نماذج معروفة للبيانات المخفية
            if b'PK' in content:  # ملف ZIP مخفي
                hidden_data['zip_hidden'] = True

            if b'<?php' in content or b'<script>' in content:
                hidden_data['suspicious_code'] = True

    except Exception as e:
        hidden_data['error'] = str(e)

    return hidden_data


def extract_text_with_ocr(image_path):
    """استخراج النصوص من الصورة باستخدام OCR مع تحسين"""
    try:
        # تحسين جودة الصورة لتحسين دقة OCR
        img = Image.open(image_path)

        # تحسين الصورة لتحسين دقة OCR
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # زيادة التباين إذا كانت الصورة باهتة
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(2.0)

        # استخدام OCR لاستخراج النص
        custom_config = r'--oem 3 --psm 6 -l eng+ara'
        text = pytesseract.image_to_string(img, config=custom_config)

        return text.strip() if text else "لم يتم العثور على نص"
    except Exception as e:
        return f"Error in OCR: {str(e)}"


def analyze_text_content(text):
    """تحليل محتوى النص للكشف عن المحتوى الضار"""
    threats = []

    # إذا كان النص فارغاً أو رسالة خطأ
    if not text or "Error in OCR" in text:
        return {
            'threats': threats,
            'language': 'unknown',
            'text_length': 0,
            'unique_threats': 0
        }

    # قائمة بالكلمات والعبارات المشبوهة
    malicious_patterns = {
        'phishing': [
            r'دعوة عاجلة', r'فرصة ذهبية', r'ربح جائزة', r'تحديث الحساب',
            r'أمن المعلومات', r'تأكيد الهوية', r'كلمة المرور', r'اسم المستخدم',
            r'الرجاء التسجيل', r'عرض محدود', r'http?://', r'www\.',
            r'@[^\s]+', r'#\w+', r'سجل دخولك', r'اضغط هنا'
        ],
        'malicious': [
            r'فيروس', r'برمجية خبيثة', r'احتيال', r'نصب',
            r'قرصنة', r'اختراق', r'تهديد', r'خطر',
            r'تصيد', r'احتيال إلكتروني', r'برنامج ضار'
        ],
        'sensitive': [
            r'\d{16}',  # أرقام بطاقات الائتمان
            r'\d{3}-\d{2}-\d{4}',  # رقم الضمان الاجتماعي
            r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',  # عناوين البريد الإلكتروني
            r'\d{10,}',  # أرقام طويلة (هواتف)
            r'(\+?\d{1,3}[-.\s]?)?(\()?\d{3}(\))?[-.\s]?\d{3}[-.\s]?\d{4}'  # هواتف
        ]
    }

    # تحليل النص للعثور على الأنماط الضارة
    for category, patterns in malicious_patterns.items():
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                threats.append({
                    'category': category,
                    'pattern': pattern,
                    'matches': matches,
                    'count': len(matches)
                })

    # تحليل اللغة
    try:
        lang = detect(text) if text else 'unknown'
    except LangDetectException:
        lang = 'unknown'

    return {
        'threats': threats,
        'language': lang,
        'text_length': len(text),
        'unique_threats': len(threats)
    }


def detect_hidden_text(image_path):
    """الكشف عن النص المخفي باستخدام معالجة الصور"""
    try:
        img = Image.open(image_path)

        # تحويل الصورة إلى تدرجات الرمادي
        gray_img = img.convert('L')

        # زيادة التباين للكشف عن النص المخفي
        enhancer = ImageEnhance.Contrast(gray_img)
        enhanced_img = enhancer.enhance(3.0)

        # تطبيق مرشح للكشف عن الحواف
        edges = enhanced_img.filter(ImageFilter.FIND_EDGES)

        # استخراج النص من الصورة المحسنة
        hidden_text = pytesseract.image_to_string(edges)

        return hidden_text.strip()
    except Exception as e:
        return f"Error in hidden text detection: {str(e)}"


def scan_with_virustotal(file_path, api_key):
    """مسح الصورة باستخدام VirusTotal API"""
    results = {}

    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': api_key}

        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            response = requests.post(url, files=files, params=params)

            if response.status_code == 200:
                scan_results = response.json()
                results['vt_scan_id'] = scan_results.get('scan_id')
                results['vt_permalink'] = scan_results.get('permalink')
            else:
                results['error'] = f"VirusTotal API error: {response.status_code}"

    except Exception as e:
        results['error'] = str(e)

    return results


def get_virustotal_report(scan_id, api_key):
    """الحصول على تقرير VirusTotal"""
    results = {}

    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': scan_id}

        response = requests.get(url, params=params)

        if response.status_code == 200:
            report = response.json()
            results['vt_report'] = report

            # تحليل النتائج
            if report.get('response_code') == 1:
                positives = report.get('positives', 0)
                total = report.get('total', 0)
                results['positives'] = positives
                results['total'] = total
                results['score'] = f"{positives}/{total}"
            else:
                # تعيين قيم افتراضية إذا لم يكن response_code = 1
                results['positives'] = 0
                results['total'] = 0
                results['score'] = "0/0"
                results['error'] = f"Response code: {report.get('response_code')}"
        else:
            results['error'] = f"VirusTotal API error: {response.status_code}"
            # تعيين قيم افتراضية في حالة الخطأ
            results['positives'] = 0
            results['total'] = 0
            results['score'] = "0/0"

    except Exception as e:
        results['error'] = str(e)
        # تعيين قيم افتراضية في حالة الاستثناء
        results['positives'] = 0
        results['total'] = 0
        results['score'] = "0/0"

    return results


def analyze_image_comprehensive(image_path, virustotal_api_key=None, ml_model=None, phishing_detector=None,
                                behavioral_analyzer=None, threat_intelligence=None):
    """تحليل شامل للصورة مع الميزات الجديدة"""
    analysis_results = {}

    try:
        # 1. الحصول على معلومات نوع الملف
        analysis_results['file_info'] = get_file_type_info(image_path)

        # 2. تحليل البيانات الوصفية
        analysis_results['metadata'] = analyze_image_metadata(image_path)

        # 3. فقط تابع التحليل إذا كان الملف صورة معروفة
        mime_type = analysis_results['file_info'].get('mime_type', '')
        known_image_types = ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/tiff']

        if mime_type in known_image_types:
            # 4. الكشف عن البيانات المخفية
            analysis_results['hidden_data'] = check_hidden_data(image_path)

            # 5. استخراج النصوص باستخدام OCR
            extracted_text = extract_text_with_ocr(image_path)
            analysis_results['extracted_text'] = extracted_text

            # 6. تحليل النص المستخرج
            analysis_results['text_analysis'] = analyze_text_content(extracted_text)

            # 7. الكشف عن النص المخفي
            hidden_text = detect_hidden_text(image_path)
            analysis_results['hidden_text'] = hidden_text
            analysis_results['hidden_text_analysis'] = analyze_text_content(hidden_text)

            # 8. استخدام نموذج تعلم الآلة للكشف (إذا كان متوفراً)
            if ml_model:
                try:
                    ml_score = ml_model.predict(image_path)
                    analysis_results['ml_analysis'] = {
                        'malware_score': float(ml_score),
                        'is_malicious': ml_score > 0.7
                    }
                except Exception as e:
                    analysis_results['ml_analysis'] = {
                        'malware_score': 0.0,
                        'is_malicious': False,
                        'error': str(e)
                    }
            else:
                # تعيين قيم افتراضية إذا لم يكن نموذج ML متاحًا
                analysis_results['ml_analysis'] = {
                    'malware_score': 0.0,
                    'is_malicious': False
                }

            # 9. تحليل التصيد المتقدم (إذا كان متوفراً)
            if phishing_detector:
                combined_text = f"{extracted_text} {hidden_text}"
                phishing_score = phishing_detector.predict_phishing(combined_text)
                analysis_results['advanced_phishing_analysis'] = {
                    'phishing_score': phishing_score,
                    'is_phishing': phishing_score > 0.7
                }

            # 10. التحليل السلوكي (إذا كان متوفراً)
            if behavioral_analyzer:
                analysis_results['behavioral_analysis'] = behavioral_analyzer.analyze_behavioral_patterns(image_path)

            # 11. المسح باستخدام VirusTotal (إذا كان API key متوفراً)
            if virustotal_api_key:
                try:
                    vt_scan = scan_with_virustotal(image_path, virustotal_api_key)
                    analysis_results['virustotal_scan'] = vt_scan

                    if 'vt_scan_id' in vt_scan:
                        import time
                        time.sleep(15)
                        vt_report = get_virustotal_report(vt_scan['vt_scan_id'], virustotal_api_key)
                        analysis_results['virustotal_report'] = vt_report
                    else:
                        # تعيين تقرير افتراضي إذا فشل المسح
                        analysis_results['virustotal_report'] = {
                            'positives': 0,
                            'total': 0,
                            'score': "0/0",
                            'error': 'Failed to get scan ID'
                        }
                except Exception as e:
                    analysis_results['virustotal_report'] = {
                        'positives': 0,
                        'total': 0,
                        'score': "0/0",
                        'error': str(e)
                    }
            else:
                # تعيين تقرير افتراضي إذا لم يكن API key متوفرًا
                analysis_results['virustotal_report'] = {
                    'positives': 0,
                    'total': 0,
                    'score': "0/0",
                    'error': 'VirusTotal API key not available'
                }

            # 12. Threat Intelligence (إذا كان متوفراً)
            if threat_intelligence:
                file_hash = calculate_file_hash(image_path)
                analysis_results['threat_intelligence'] = threat_intelligence.check_hash_reputation(file_hash)

            # 13. تحديد ما إذا كانت الصورة ضارة بناءً على جميع النتائج
            threat_score = 0.0
            threat_types = []

            # التهديدات من البيانات المخفية
            if analysis_results['hidden_data'].get('suspicious_code'):
                threat_score += 0.3
                threat_types.append("Suspicious code embedded")

            if analysis_results['hidden_data'].get('zip_hidden'):
                threat_score += 0.2
                threat_types.append("Hidden archive detected")

            # التهديدات من النص المستخرج
            if analysis_results['text_analysis'].get('unique_threats', 0) > 0:
                threat_score += min(0.3, 0.1 * analysis_results['text_analysis']['unique_threats'])
                threat_types.append(f"Suspicious text patterns: {analysis_results['text_analysis']['unique_threats']}")

            # التهديدات من النص المخفي
            if analysis_results['hidden_text_analysis'].get('unique_threats', 0) > 0:
                threat_score += min(0.4, 0.15 * analysis_results['hidden_text_analysis']['unique_threats'])
                threat_types.append(
                    f"Hidden text threats: {analysis_results['hidden_text_analysis']['unique_threats']}")

            # التهديدات من نموذج تعلم الآلة
            if analysis_results['ml_analysis'].get('is_malicious', False):
                threat_score = max(threat_score, analysis_results['ml_analysis']['malware_score'])
                threat_types.append("ML model detection")

            # التهديدات من تحليل التصيد المتقدم
            if 'advanced_phishing_analysis' in analysis_results:
                phishing_score = analysis_results['advanced_phishing_analysis'].get('phishing_score', 0.0)
                threat_score = max(threat_score, phishing_score)
                if analysis_results['advanced_phishing_analysis'].get('is_phishing', False):
                    threat_types.append("Advanced phishing detection")

            # التهديدات من التحليل السلوكي
            if 'behavioral_analysis' in analysis_results:
                if analysis_results['behavioral_analysis'].get('steganography_indications', False):
                    threat_score += 0.3
                    threat_types.append("Steganography indications")

                if analysis_results['behavioral_analysis'].get('suspicious_patterns', []):
                    threat_score += 0.2 * len(analysis_results['behavioral_analysis']['suspicious_patterns'])
                    threat_types.append(
                        f"Suspicious patterns: {len(analysis_results['behavioral_analysis']['suspicious_patterns'])}")

            # التهديدات من VirusTotal
            if analysis_results['virustotal_report'].get('positives', 0) > 0:
                vt_score = analysis_results['virustotal_report']['positives'] / analysis_results['virustotal_report'][
                    'total']
                threat_score = max(threat_score, vt_score)
                threat_types.append(
                    f"Detected by {analysis_results['virustotal_report']['positives']} antivirus engines")

            # التهديدات من Threat Intelligence
            if 'threat_intelligence' in analysis_results:
                vt_positives = analysis_results['threat_intelligence'].get('virustotal', {}).get('positives', 0)
                if vt_positives > 0:
                    threat_score = max(threat_score, vt_positives / 100)
                    threat_types.append(f"Threat intelligence: {vt_positives} detections")

            analysis_results['is_malicious'] = threat_score > 0.5
            analysis_results['threat_score'] = min(threat_score, 1.0)
            analysis_results['threat_type'] = ", ".join(threat_types) if threat_types else "No threats detected"

        else:
            # إذا لم يكن الملف صورة معروفة، ضع رسالة مناسبة
            analysis_results['skipped_analysis'] = True
            analysis_results['reason'] = f"نوع الملف غير مدعوم: {mime_type}"
            analysis_results['is_malicious'] = False
            analysis_results['threat_score'] = 0.0
            analysis_results['threat_type'] = "Unsupported file type"

    except Exception as e:
        analysis_results['analysis_error'] = str(e)
        analysis_results['is_malicious'] = False
        analysis_results['threat_score'] = 0.0
        analysis_results['threat_type'] = f"Analysis error: {str(e)}"

    return analysis_results