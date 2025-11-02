"""import os
import time
import subprocess
import winreg

import psutil
from datetime import datetime
from config import Config
import logging
import socket


class Sandbox:
    def __init__(self, file_path):
        self.file_path = file_path
        self.results = {}
        self.logger = logging.getLogger('sandbox')
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename='sandbox.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def run(self):
        if not Config.DYNAMIC_ANALYSIS_ENABLED:
            return {"status": "disabled", "message": "التحليل الديناميكي معطل"}

        try:
            start_time = datetime.utcnow()

            # تحليل ديناميكي حقيقي
            self.results = {
                "file_info": self.get_file_info(),
                "process_activity": self.monitor_process(),
                "network_activity": self.capture_network_activity(),
                "file_operations": self.track_file_operations(),
                "registry_changes": self.check_registry_changes(),
                "start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
                "end_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                "verdict": "غير محدد"
            }

            self.analyze_results()
            return self.results

        except Exception as e:
            self.logger.error(f"Error in dynamic analysis: {str(e)}")
            return {"status": "error", "message": str(e)}

    def get_file_info(self):

        return {
            "filename": os.path.basename(self.file_path),
            "size": os.path.getsize(self.file_path),
            "modified": datetime.fromtimestamp(os.path.getmtime(self.file_path)).strftime('%Y-%m-%d %H:%M:%S'),
            "type": self.detect_file_type()
        }

    def detect_file_type(self):

        try:
            result = subprocess.run(['file', '--brief', self.file_path],
                                    capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "Unknown"

    def monitor_process(self):

        activities = []
        try:
            # تشغيل الملف في عملية منفصلة
            proc = subprocess.Popen(
                self.file_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

            # مراقبة العملية لمدة 30 ثانية
            timeout = time.time() + 30
            while time.time() < timeout and proc.poll() is None:
                try:
                    p = psutil.Process(proc.pid)
                    activities.append({
                        "pid": proc.pid,
                        "cpu_percent": p.cpu_percent(),
                        "memory_info": p.memory_info()._asdict(),
                        "open_files": [f.path for f in p.open_files()],
                        "connections": [conn._asdict() for conn in p.connections()],
                        "threads": p.num_threads(),
                        "timestamp": datetime.utcnow().strftime('%H:%M:%S')
                    })
                    time.sleep(1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break

            # إنهاء العملية إذا كانت لا تزال تعمل
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        except Exception as e:
            self.logger.error(f"Process monitoring failed: {str(e)}")

        return activities

    def capture_network_activity(self):

        activities = []
        try:
            # استخدام socket لمراقبة الاتصالات
            orig_socket = socket.socket

            def socket_logger(*args, **kwargs):
                s = orig_socket(*args, **kwargs)
                activities.append({
                    "action": "socket_created",
                    "family": args[0] if args else kwargs.get('family'),
                    "type": args[1] if len(args) > 1 else kwargs.get('type'),
                    "proto": args[2] if len(args) > 2 else kwargs.get('proto'),
                    "timestamp": datetime.utcnow().strftime('%H:%M:%S')
                })
                return s

            socket.socket = socket_logger

            # تنفيذ الملف مع مراقبة الشبكة
            proc = subprocess.Popen(
                self.file_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            time.sleep(30)

            # استعادة socket الأصلي
            socket.socket = orig_socket

            if proc.poll() is None:
                proc.terminate()

        except Exception as e:
            self.logger.error(f"Network monitoring failed: {str(e)}")
            socket.socket = orig_socket

        return activities

    def track_file_operations(self):

        operations = []
        try:
            # يمكن استبدال هذا بأدوات أكثر تطوراً مثل فيلمون أو بايثون فيمون
            proc = subprocess.Popen(
                self.file_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

            # مراقبة مجلد مؤقت
            temp_dir = "temp_monitor"
            os.makedirs(temp_dir, exist_ok=True)

            # هنا يمكن إضافة منطق لمراقبة التغييرات في الملفات
            # هذا مثال مبسط فقط
            time.sleep(30)

            if proc.poll() is None:
                proc.terminate()

        except Exception as e:
            self.logger.error(f"File operations tracking failed: {str(e)}")

        return operations

    def check_registry_changes(self):

        changes = []
        try:
            if os.name == 'nt':
                import winreg

                # مراقبة بعض مفاتيح السجل المهمة
                keys_to_monitor = [
                    (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
                ]

                for hive, key in keys_to_monitor:
                    try:
                        before = self.read_registry_key(hive, key)

                        proc = subprocess.Popen(
                            self.file_path,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True
                        )
                        time.sleep(30)

                        if proc.poll() is None:
                            proc.terminate()

                        after = self.read_registry_key(hive, key)

                        if before != after:
                            changes.append({
                                "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                                "key": key,
                                "changes": {"before": before, "after": after}
                            })
                    except Exception as e:
                        self.logger.error(f"Registry monitoring failed for {key}: {str(e)}")

        except ImportError:
            self.logger.warning("Registry monitoring is only available on Windows")

        return changes

    def read_registry_key(self, hive, key):

        values = {}
        try:
            with winreg.OpenKey(hive, key) as reg_key:
                for i in range(0, winreg.QueryInfoKey(reg_key)[1]):
                    try:
                        name, value, _ = winreg.EnumValue(reg_key, i)
                        values[name] = value
                    except OSError:
                        continue
        except WindowsError:
            pass
        return values

    def analyze_results(self):

        malicious_indicators = 0

        # تحليل نشاط العملية
        for activity in self.results["process_activity"]:
            if activity.get("open_files"):
                for file in activity["open_files"]:
                    if "system32" in file.lower():
                        malicious_indicators += 1

            if activity.get("connections"):
                malicious_indicators += len(activity["connections"])

        # تحليل النشاط الشبكي
        malicious_indicators += len(self.results["network_activity"])

        # تحليل تغييرات السجل
        malicious_indicators += len(self.results["registry_changes"])

        # تحديد الحكم النهائي
        if malicious_indicators > 5:
            self.results["verdict"] = "خبيث"
        elif malicious_indicators > 2:
            self.results["verdict"] = "مشبوه"
        else:
            self.results["verdict"] = "آمن"
           """

import os
import time
import random
from datetime import datetime
from config import Config


class Sandbox:
    def __init__(self, file_path):
        self.file_path = file_path
        self.results = {}

    def run(self):
        if not Config.DYNAMIC_ANALYSIS_ENABLED:
            return {"status": "disabled", "message": "التحليل الديناميكي معطل"}

        try:
            time.sleep(random.uniform(2, 5))

            self.results = {
                "status": "completed",
                "start_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                "end_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                "behavior_indicators": self._simulate_behavior(),
                "network_activity": self._simulate_network(),
                "file_operations": self._simulate_file_ops(),
                "registry_changes": self._simulate_registry(),
                "score": random.randint(0, 100),
                "verdict": random.choice(["آمن", "مشبوه", "خبيث"])
            }
            return self.results

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _simulate_behavior(self):
        behaviors = []
        possible_behaviors = [
            "إنشاء عملية جديدة",
            "تعديل سجل النظام",
            "الوصول إلى ملفات حساسة",
            "الاتصال بخادم بعيد",
            "تحميل مكتبات ديناميكية",
            "محاولة إخفاء العملية",
            "حقن كود في عمليات أخرى",
            "تعديل إعدادات الجدار الناري"
        ]

        for _ in range(random.randint(1, 5)):
            behaviors.append(random.choice(possible_behaviors))

        return behaviors

    def _simulate_network(self):
        activities = []
        domains = [
            "malicious-domain.com",
            "data-exfiltrate.net",
            "cnc-server.org",
            "legit-website.com",
            "update-server.example"
        ]

        for _ in range(random.randint(0, 3)):
            activities.append({
                "type": random.choice(["DNS Query", "HTTP Request", "TCP Connection"]),
                "target": random.choice(domains),
                "port": random.randint(80, 50000)
            })

        return activities

    def _simulate_file_ops(self):
        operations = []
        paths = [
            "C:\\Windows\\System32",
            "C:\\ProgramData",
            "C:\\Users\\Public",
            "C:\\Temp",
            "D:\\Documents"
        ]

        for _ in range(random.randint(0, 4)):
            operations.append({
                "operation": random.choice(["Create", "Modify", "Delete"]),
                "path": f"{random.choice(paths)}\\{random.choice(['config.ini', 'data.bin', 'key.txt', 'payload.exe'])}"
            })

        return operations

    def _simulate_registry(self):
        changes = []
        keys = [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "HKCU\\Environment",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services"
        ]

        for _ in range(random.randint(0, 3)):
            changes.append({
                "key": random.choice(keys),
                "value": random.choice(["StartupItem", "Debugger", "SafeBoot", "AutoRun"]),
                "data": random.choice(["malware.exe", "svchost.dll", "explorer.exe"])
            })

        return changes

