import math
import os
import hashlib
import pandas as pd
import pefile
import time
import joblib
import uuid
from datetime import datetime
import re
import subprocess
import logging

from flask import current_app

logger = logging.getLogger(__name__)

# ---------------- Allowed File ----------------
def allowed_file_exe(filename):
    allowed_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {'exe', 'dll', 'bin', 'sys', 'scr', 'cpl'})
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# ---------------- File Hash ----------------
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

# ---------------- Safe Delete ----------------
def safe_delete(file_path, max_retries=5, delay=1):
    if not os.path.exists(file_path):
        return True
    for i in range(max_retries):
        try:
            os.unlink(file_path)
            return True
        except (PermissionError, OSError) as e:
            if not os.path.exists(file_path):
                return True
            if i == max_retries - 1:
                current_app.logger.error(f"فشل حذف الملف بعد {max_retries} محاولات: {file_path}, الخطأ: {str(e)}")
                return False
            time.sleep(delay)
    return False

# ---------------- PE Feature Extraction ----------------
def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

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

        imports_info = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                functions = [imp.name.decode('utf-8', errors='ignore').lower() for imp in entry.imports if imp.name]
                imports_info[dll_name] = functions

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

# ---------------- Model Prediction ----------------
def predict_sample(file_path):
    try:
        model = joblib.load(current_app.config['MODEL_PATH'])
        FEATURE_NAMES = list(model.feature_names_in_)

        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

        feature_vector = {
            'e_magic': pe.OPTIONAL_HEADER.Magic,
            'e_cblp': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'e_cp': pe.FILE_HEADER.NumberOfSections,
            'e_crlc': pe.FILE_HEADER.NumberOfSymbols,
            'e_cparhdr': pe.FILE_HEADER.SizeOfOptionalHeader,
        }

        for i, sec in enumerate(pe.sections[:5]):
            feature_vector[f'Section_{i}_Entropy'] = round(sec.get_entropy(), 3)
            feature_vector[f'Section_{i}_RawSize'] = sec.SizeOfRawData
            feature_vector[f'Section_{i}_VirtualSize'] = sec.Misc_VirtualSize

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

        for feature in FEATURE_NAMES:
            if feature not in feature_vector:
                feature_vector[feature] = 0

        df = pd.DataFrame([feature_vector])
        df = df[FEATURE_NAMES]
        pred = model.predict(df)[0]
        proba = model.predict_proba(df)[0][1] if hasattr(model, 'predict_proba') else None
        return pred, proba
    except Exception as e:
        current_app.logger.error(f"خطأ في التصنيف: {str(e)}")
        return 0, 0.0

# ---------------- String Extraction ----------------
def extract_strings(file_path, min_length=4):
    results = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
        for match in pattern.finditer(data):
            results.append({'offset': match.start(), 'string': match.group().decode('utf-8', errors='ignore')})
    except Exception as e:
        logger.error(f"خطأ في استخراج النصوص: {str(e)}")
    return results

# ---------------- Entropy & Packing ----------------
def analyze_entropy(file_path):
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
                entropy += - p_x * math.log2(p_x)
        return entropy
    except Exception as e:
        logger.error(f"خطأ في تحليل الإنتروبي: {str(e)}")
        return 0.0

def detect_packing(file_path):
    entropy = analyze_entropy(file_path)
    return entropy > 7.0, entropy

# ---------------- Network Indicators ----------------
def analyze_network_indicators(strings):
    ips, urls, domains = [], [], []
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|info|io|co|me|tech|biz|dev|app|online|site|xyz|ai|uk|us|ca|de|fr|jp|cn|ru|in|au|br|za|nl|se|no|es|it|ch|pl|cz|gr|fi|dk|be|at|cz|hu|ro|tr|eu)\b'
    text_items = [item['string'] if isinstance(item, dict) else item for item in strings]
    for text in text_items:
        ips.extend(re.findall(ip_pattern, text))
        urls.extend(re.findall(url_pattern, text))
        domains.extend(re.findall(domain_pattern, text))
    return {'ips': list(set(ips)), 'urls': list(set(urls)), 'domains': list(set(domains))}

# ---------------- YARA ----------------
try:
    import yara
except ImportError:
    yara = None
    logger.warning("مكتبة YARA غير موجودة، سيتم تخطي تحليل القواعد.")

def apply_yara_rules(file_path):
    matches = []
    if not yara:
        return matches
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(base_dir, 'yara-rules')
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
            return matches
        yara_files = [f for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara'))]
        for yara_file in yara_files:
            try:
                rules = yara.compile(filepath=os.path.join(rules_dir, yara_file))
                for match in rules.match(file_path):
                    matches.append({'rule': match.rule, 'tags': ','.join(match.tags), 'description': getattr(match, 'meta', {}).get('description','')})
            except Exception as e:
                logger.error(f"خطأ في قاعدة YARA {yara_file}: {str(e)}")
    except Exception as e:
        logger.error(f"خطأ أثناء فحص YARA: {str(e)}")
    return matches

# ---------------- Libraries Extraction ----------------
def extract_libraries(file_path):
    libraries = set()
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                libraries.add(entry.dll.decode('utf-8', errors='ignore').lower())
    except Exception as e:
        logger.error(f"خطأ في استخراج المكتبات: {str(e)}")
    return list(libraries)
