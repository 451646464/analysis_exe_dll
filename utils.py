import math
import os
import hashlib
import pandas as pd
import pefile
import time
import joblib
import uuid
from datetime import datetime, timedelta
import re
import requests
import yara
from flask import current_app

from models import AnalysisSample
from database import db

import logging
logger = logging.getLogger(__name__)
def allowed_file_exe(filename):
    # استخدام القيمة الافتراضية إذا لم يكن الإعداد متاحًا
    allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'exe', 'dll', 'bin', 'sys', 'scr', 'cpl'})
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in allowed_extensions
def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        current_app.logger.error(f"خطأ في حساب البصمة: {str(e)}")
        raise


def safe_delete(file_path, max_retries=5, delay=1):
    """حذف ملف مع إعادة المحاولة في حال كان قيد الاستخدام."""
    # إذا كان الملف غير موجود، لا نحتاج لفعل شيء
    if not os.path.exists(file_path):
        return True

    for i in range(max_retries):
        try:
            os.unlink(file_path)
            return True
        except (PermissionError, OSError) as e:
            # إذا كان الخطأ لأن الملف غير موجود (تم حذفه بالفعل)
            if not os.path.exists(file_path):
                return True

            # إذا كانت المحاولة الأخيرة
            if i == max_retries - 1:
                current_app.logger.error(f"فشل حذف الملف بعد {max_retries} محاولات: {file_path}, الخطأ: {str(e)}")
                return False

            # انتظر قبل إعادة المحاولة
            time.sleep(delay)

    return False


def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])

        # استخراج معلومات الرأس
        header_info = {
            'Machine': pe.FILE_HEADER.Machine,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'TimeDateStamp': datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
            'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
            'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'Magic': pe.OPTIONAL_HEADER.Magic,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        }

        # استخراج معلومات الأقسام
        sections_info = []
        for sec in pe.sections:
            section_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
            sections_info.append({
                'Name': section_name,
                'VirtualAddress': hex(sec.VirtualAddress),
                'VirtualSize': sec.Misc_VirtualSize,
                'RawSize': sec.SizeOfRawData,
                'Entropy': round(sec.get_entropy(), 3),
                'Characteristics': sec.Characteristics
            })

        # استخراج الواردات
        imports_info = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore').lower()
                        functions.append(func_name)
                imports_info[dll_name] = functions

        # مؤشرات ديناميكية
        dynamic_indicators = []
        malicious_dlls = ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll']
        malicious_apis = ['createthread', 'createprocess', 'regsetvalue', 'socket', 'connect']

        for dll, functions in imports_info.items():
            if dll in malicious_dlls:
                dynamic_indicators.append(f"DLL مشبوه: {dll}")
            for func in functions:
                if any(api in func for api in malicious_apis):
                    dynamic_indicators.append(f"API مشبوه: {func}")

        return header_info, sections_info, imports_info, dynamic_indicators

    except Exception as e:
        current_app.logger.error(f"خطأ في استخراج الميزات: {str(e)}")
        return {}, [], {}, []


def predict_sample(file_path):
    try:
        model = joblib.load(current_app.config['MODEL_PATH'])
        FEATURE_NAMES = list(model.feature_names_in_)

        # بناء متجه الميزات
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])

        # ميزات الرأس
        feature_vector = {
            'e_magic': pe.OPTIONAL_HEADER.Magic,
            'e_cblp': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'e_cp': pe.FILE_HEADER.NumberOfSections,
            'e_crlc': pe.FILE_HEADER.NumberOfSymbols,
            'e_cparhdr': pe.FILE_HEADER.SizeOfOptionalHeader,
        }

        # ميزات الأقسام
        for i, sec in enumerate(pe.sections[:5]):
            feature_vector[f'Section_{i}_Entropy'] = round(sec.get_entropy(), 3)
            feature_vector[f'Section_{i}_RawSize'] = sec.SizeOfRawData
            feature_vector[f'Section_{i}_VirtualSize'] = sec.Misc_VirtualSize

        # ميزات الواردات
        dlls, apis = set(), set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.add(entry.dll.decode(errors='ignore').lower())
                for imp in entry.imports:
                    if imp.name:
                        apis.add(imp.name.decode(errors='ignore').lower())

        for name in dlls:
            if name in FEATURE_NAMES:
                feature_vector[name] = 1
        for name in apis:
            if name in FEATURE_NAMES:
                feature_vector[name] = 1

        # ملء القيم المفقودة
        for feature in FEATURE_NAMES:
            if feature not in feature_vector:
                feature_vector[feature] = 0

        # التصنيف
        df = pd.DataFrame([feature_vector])
        df = df[FEATURE_NAMES]
        pred = model.predict(df)[0]
        proba = model.predict_proba(df)[0][1] if hasattr(model, 'predict_proba') else None

        return pred, proba

    except Exception as e:
        current_app.logger.error(f"خطأ في التصنيف: {str(e)}")
        return 0, 0.0


def generate_pdf_report(html_content, filename):
    try:
        from xhtml2pdf import pisa
        # إنشاء مجلد التقارير إذا لم يكن موجوداً
        reports_folder = current_app.config['REPORTS_FOLDER']
        os.makedirs(reports_folder, exist_ok=True)

        pdf_path = os.path.join(reports_folder, filename)

        with open(pdf_path, "wb") as result_file:
            pisa_status = pisa.CreatePDF(
                html_content,
                dest=result_file,
                encoding='utf-8'
            )

        if pisa_status.err:
            current_app.logger.error(f"PDF generation error: {pisa_status.err}")
            return None

        return pdf_path
    except Exception as e:
        current_app.logger.error(f"PDF generation exception: {str(e)}")
        return None



def extract_strings(file_path, min_length=4):

    """استخراج السلاسل النصية من الملف مع مواضعها (offsets)"""
    results = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
        # pattern كـ bytes

        for match in pattern.finditer(data):
            results.append({
                'offset': match.start(),
                'string': match.group().decode('utf-8', errors='ignore')
            })
    except Exception as e:
        logger.error(f"Error extracting strings: {e}")
    return results
import subprocess



def run_binwalk(file_path):
    """تحليل الملف باستخدام binwalk كأداة خارجية"""
    results = []
    try:
        # تشغيل binwalk باستخدام subprocess
        process = subprocess.run(
            ['binwalk', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if process.returncode != 0:
            print("Binwalk error:", process.stderr)
            return results

        lines = process.stdout.splitlines()

        # استخراج النتائج من السطور
        parsing = False
        for line in lines:
            if line.strip().startswith('DECIMAL'):
                parsing = True
                continue
            if parsing and line.strip():
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    offset, _, description = parts
                    results.append({
                        'offset': offset,
                        'description': description,
                        'type': 'binwalk'
                    })
    except Exception as e:
        print(f"Binwalk execution failed: {str(e)}")
    return results
def analyze_entropy(file_path):

    """تحليل إنتروبيا الملف"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        if not data:
            return 0.0

        entropy = 0.0
        size = len(data)
        for x in range(256):
            p_x = float(data.count(x)) / size
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)

        return entropy
    except Exception as e:
        logger.error(f"Entropy calculation error: {str(e)}")
        return 0.0


def detect_packing(file_path):
    """الكشف عن ملفات مضغوطة"""
    entropy = analyze_entropy(file_path)
    packed = entropy > 7.0  # إنتروبيا عالية تشير إلى ضغط أو تشفير
    return packed, entropy




def analyze_network_indicators(strings):
    """تحليل مؤشرات الشبكة في السلاسل النصية"""
    ips = []
    urls = []
    domains = []

    # أنماط للكشف عن عناوين IP وURLs
    ip_pattern     = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_pattern    = r'https?://[^\s/$.?#].[^\s]*'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|info|io|co|me|tech|biz|dev|app|online|site|xyz|ai|uk|us|ca|de|fr|jp|cn|ru|in|au|br|za|nl|se|no|es|it|ch|pl|cz|gr|fi|dk|be|at|cz|hu|ro|tr|eu)\b'


    # استخرج النصوص فقط: إذا كان العنصر dict خذ قيمة 'string'
    text_items = []
    for item in strings:
        if isinstance(item, dict) and 'string' in item:
            text_items.append(item['string'])
        elif isinstance(item, str):
            text_items.append(item)
        else:
            # تجاهل أي أنواع أخرى
            continue

    # طبق الأنماط على النصوص
    for text in text_items:
        ips.extend(re.findall(ip_pattern, text))
        urls.extend(re.findall(url_pattern, text))
        domains.extend(re.findall(domain_pattern, text))

    return {
        'ips':     list(set(ips)),
        'urls':    list(set(urls)),
        'domains': list(set(domains))
    }








def apply_yara_rules(file_path):
    matches = []
    try:
        # نحصل على مسار المجلد الذي يحتوي هذا السكربت
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(base_dir, 'yara-rules')  # مجلد القواعد داخل مجلد السكربت نفسه

        # نتحقق من وجود المجلد بشكل صحيح
        if not os.path.exists(rules_dir):
            logger.warning(f"مجلد القواعد غير موجود: {rules_dir}. سيتم إنشاؤه.")
            os.makedirs(rules_dir)
            return matches  # لا توجد قواعد للفحص

        # نقرأ ملفات القواعد فقط من المجلد الصحيح
        yara_files = [f for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))]
        if not yara_files:
            logger.warning(f"لا توجد ملفات قواعد في {rules_dir}")
            return matches

        # نُركب قواعد yara من كل ملف ونطبقها على الملف المُدخل
        for yara_file in yara_files:
            try:
                rules = yara.compile(os.path.join(rules_dir, yara_file))
                for match in rules.match(file_path):
                    matches.append({
                        'rule': match.rule,
                        'tags': ', '.join(match.tags),
                        'description': match.meta.get('description', '') if hasattr(match, 'meta') else ''
                    })
            except Exception as e:
                logger.error(f"خطأ في قاعدة YARA {yara_file}: {str(e)}")
    except Exception as e:
        logger.error(f"خطأ أثناء فحص YARA: {str(e)}")
    return matches


def extract_libraries(file_path):

    """استخراج المكتبات المستخدمة"""
    libraries = set()
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # إصلاح: إرجاع أسماء المكتبات كسلاسل نصية كاملة
                lib_name = entry.dll.decode('utf-8', errors='ignore').lower()
                libraries.add(lib_name)
    except Exception as e:
        logger.error(f"Error extracting libraries: {str(e)}")
    return list(libraries)


def extract_powershell_commands(strings):
    """استخراج أوامر PowerShell من السلاسل النصية"""
    commands = []
    pattern = r'\b(?:powershell|pwsh|\.ps1)\b'

    for item in strings:
        # التعامل مع جميع أنواع البيانات بشكل صحيح
        if isinstance(item, dict):
            text = item['string']
        else:
            text = item

        if re.search(pattern, text, re.IGNORECASE):
            commands.append(text)

    return commands


def analyze_persistence_mechanisms(strings):
    """تحليل مؤشرات الإصرار (persistence mechanisms)"""
    indicators = []
    patterns = [
        r'(?:HKLM|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[^\s]+',
        r'schtasks\s+/Create\s+/TN\s+\"[^\"]+\"',
        r'sc\s+(?:create|start)\s+[^\s]+',
    ]

    text_items = []
    for item in strings:
        # معالجة جميع أنواع البيانات
        if isinstance(item, dict):
            text = item['string']
        else:
            text = item
        text_items.append(text)

    # إزالة التكرارات مع الحفاظ على الترتيب
    unique_texts = list(dict.fromkeys(text_items))

    for pattern in patterns:
        for text in unique_texts:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(text)

    return indicators

def detect_c2_servers(domains, ips):
    """الكشف عن خوادم C2"""
    c2_indicators = []
    # قاعدة بيانات بسيطة لمؤشرات C2 المعروفة
    known_c2 = [ 'c2server', 'commandcontrol', 'malwarecnc', 'botnet',
    'cnc', 'control', 'cmdsrv', 'malicious', 'evilserver']

    for domain in domains:
        if any(c2 in domain for c2 in known_c2):
            c2_indicators.append(domain)

    for ip in ips:
        # التحقق من سمعة IP
        if check_ip_reputation(ip):
            c2_indicators.append(ip)

    return c2_indicators


def check_ip_reputation(ip):
    """التحقق من سمعة IP باستخدام AbuseIPDB"""
    try:
        api_key = os.environ.get('cd898b1adcca5dd4a517037332f22cc83a6a4f960946cd95ac3e7810beb8c8de832aeea2fa5cf1ee')
        if not api_key:
            return False

        response = requests.get(
            f'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip},
            headers={'Key': api_key, 'Accept': 'application/json'}
        )

        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('abuseConfidenceScore', 0) > 50
    except Exception:
        pass
    return False

import json
import os

def mitre_attck_mapping(indicators):
    with open("Data/enterprise-attack.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []
    text_items = []

    for ind in indicators:
        if isinstance(ind, dict) and 'string' in ind:
            text_items.append(ind['string'])
        elif isinstance(ind, str):
            text_items.append(ind)

    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            tech_name = obj.get("name", "").lower()
            tech_id = next(
                (ext['external_id'] for ext in obj.get("external_references", [])
                 if ext.get("source_name") == "mitre-attack" and "external_id" in ext),
                None
            )

            if not tech_id:
                continue

            for text in text_items:
                if tech_name in text.lower():
                    results.append({
                        "text": text,
                        "technique": tech_id,
                        "technique_name": obj.get("name")
                    })

    # إزالة التكرارات
    unique = []
    seen = set()
    for entry in results:
        key = (entry['text'], entry['technique'])
        if key not in seen:
            seen.add(key)
            unique.append(entry)

    return unique

def create_share_link(sample_id, expiry_days=7):
    sample = AnalysisSample.query.get(sample_id)
    if not sample:
        return None

    # إنشاء رمز مشاركة فريد
    sample.share_token = uuid.uuid4().hex
    sample.share_expiry = datetime.utcnow() + timedelta(days=expiry_days)
    db.session.commit()

    return sample.share_token