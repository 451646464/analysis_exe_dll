import numpy as np
from PIL import Image, ImageStat, ImageFilter, ImageEnhance
import math


class BehavioralImageAnalyzer:
    def __init__(self):
        self.suspicious_patterns = []

    def analyze_behavioral_patterns(self, image_path):
        """تحليل الأنماط السلوكية في الصورة"""
        behavioral_analysis = {
            'entropy': 0.0,
            'color_distribution': {},
            'steganography_indications': False,
            'suspicious_patterns': [],
            'metadata_anomalies': False
        }

        try:
            with Image.open(image_path) as img:
                # 1. حساب الإنتروبيا (مقياس العشوائية)
                behavioral_analysis['entropy'] = self.calculate_entropy(img)

                # 2. تحليل توزيع الألوان
                behavioral_analysis['color_distribution'] = self.analyze_color_distribution(img)

                # 3. الكشف عن مؤشرات إخفاء المعلومات (Steganography)
                behavioral_analysis['steganography_indications'] = self.detect_steganography(img)

                # 4. تحليل الأنماط المشبوهة
                behavioral_analysis['suspicious_patterns'] = self.detect_suspicious_patterns(img)

                # 5. تحليل شذوذ البيانات الوصفية
                behavioral_analysis['metadata_anomalies'] = self.check_metadata_anomalies(img)

        except Exception as e:
            behavioral_analysis['error'] = str(e)

        return behavioral_analysis

    def calculate_entropy(self, img):
        """حساب إنتروبيا الصورة"""
        # تحويل الصورة إلى تدرجات الرمادي
        gray_img = img.convert('L')

        # حساب histogram
        histogram = gray_img.histogram()
        histogram_length = sum(histogram)

        # حساب الإنتروبيا
        entropy = 0.0
        for pixel in histogram:
            if pixel > 0:
                probability = pixel / histogram_length
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_color_distribution(self, img):
        """تحليل توزيع الألوان في الصورة"""
        # تحليل القنوات اللونية
        stat = ImageStat.Stat(img)

        color_analysis = {
            'mean': stat.mean,
            'median': stat.median,
            'stddev': stat.stddev,
            'extrema': stat.extrema,
            'color_dominance': self.get_color_dominance(img)
        }

        return color_analysis

    def get_color_dominance(self, img):
        """تحديد الألوان المسيطرة في الصورة"""
        # تحليل histogram للألوان
        r, g, b = img.split()

        r_hist = r.histogram()
        g_hist = g.histogram()
        b_hist = b.histogram()

        # تحديد القنوات المسيطرة
        dominance = {
            'red_dominance': max(r_hist) > max(g_hist) and max(r_hist) > max(b_hist),
            'green_dominance': max(g_hist) > max(r_hist) and max(g_hist) > max(b_hist),
            'blue_dominance': max(b_hist) > max(r_hist) and max(b_hist) > max(g_hist),
            'uniform_distribution': abs(max(r_hist) - max(g_hist)) < 1000 and abs(max(g_hist) - max(b_hist)) < 1000
        }

        return dominance

    def detect_steganography(self, img):
        """الكشف عن مؤشرات إخفاء المعلومات"""
        indicators = {
            'lsb_anomalies': self.check_lsb_anomalies(img),
            'noise_patterns': self.analyze_noise_patterns(img),
            'file_size_discrepancy': self.check_file_size_discrepancy(img)
        }

        # إذا وجدنا مؤشرين أو أكثر، نشتبه في وجود steganography
        suspicious_indicators = sum(indicators.values())
        return suspicious_indicators >= 2

    def check_lsb_anomalies(self, img):
        """فحص شذوذ bits الأقل أهمية"""
        # تحليل LSB للكشف عن أنماط غير طبيعية
        pixels = np.array(img)
        lsb_values = pixels & 1

        # حساب توزيع LSB
        unique, counts = np.unique(lsb_values, return_counts=True)

        # في الصور الطبيعية، يكون توزيع LSB متجانساً تقريباً
        if len(counts) == 2:
            ratio = counts[0] / counts[1]
            return abs(ratio - 1) > 0.2  # إذا كان غير متجانس

        return False

    def analyze_noise_patterns(self, img):
        """تحليل أنماط الضوضاء في الصورة"""
        # تحويل الصورة إلى تدرجات الرمادي
        gray_img = img.convert('L')
        pixels = np.array(gray_img)

        # حساب الانحراف المعياري للضوضاء
        noise_std = np.std(pixels)

        # إذا كان الانحراف المعياري مرتفعاً بشكل غير طبيعي
        return noise_std > 50  # قيمة افتراضية، يمكن ضبطها

    def check_file_size_discrepancy(self, img):
        """فحص تناقض حجم الملف"""
        # في حالة steganography، قد يكون حجم الملف أكبر من المتوقع
        # هذه دالة افتراضية، تحتاج إلى تحسين
        return False

    def detect_suspicious_patterns(self, img):
        """الكشف عن الأنماط المشبوهة في الصورة"""
        suspicious_patterns = []

        # 1. تحليل وجود أنماط QR code أو باركود
        if self.detect_barcode_patterns(img):
            suspicious_patterns.append('barcode_pattern')

        # 2. تحليل وجود أنماط غير طبيعية
        if self.detect_unnatural_patterns(img):
            suspicious_patterns.append('unnatural_pattern')

        # 3. تحليل وجود نص مخفي بتقنيات متقدمة
        if self.detect_hidden_text_patterns(img):
            suspicious_patterns.append('hidden_text_pattern')

        return suspicious_patterns

    def detect_barcode_patterns(self, img):
        """الكشف عن أنماط الباركود أو QR"""
        # تحويل الصورة إلى تدرجات الرمادي
        gray_img = img.convert('L')
        pixels = np.array(gray_img)

        # البحث عن أنماط الخطوط المتوازية (مؤشر للباركود)
        horizontal_var = np.var(pixels, axis=0)
        vertical_var = np.var(pixels, axis=1)

        # إذا كان هناك تباين عالي في اتجاه واحد
        return np.max(horizontal_var) > 10000 or np.max(vertical_var) > 10000

    def detect_unnatural_patterns(self, img):
        """الكشف عن أنماط غير طبيعية"""
        # تحليل الانتظام في الصورة
        pixels = np.array(img.convert('L'))

        # حساب gradient للكشف عن الحواف غير الطبيعية
        grad_x = np.abs(np.gradient(pixels, axis=1))
        grad_y = np.abs(np.gradient(pixels, axis=0))

        # إذا كان هناك الكثير من الحواف الحادة
        return np.mean(grad_x) > 30 or np.mean(grad_y) > 30

    def detect_hidden_text_patterns(self, img):
        """الكشف عن أنماط النص المخفي"""
        # استخدام مرشحات للكشف عن المناطق التي قد تحتوي على نص مخفي
        gray_img = img.convert('L')
        pixels = np.array(gray_img)

        # تطبيق مرشح للكشف عن الترددات العالية (مؤشر للنص)
        try:
            from scipy import ndimage
            kernel = np.array([[-1, -1, -1], [-1, 8, -1], [-1, -1, -1]])
            high_freq = ndimage.convolve(pixels, kernel)

            # إذا كانت هناك مناطق ذات ترددات عالية بشكل غير طبيعي
            return np.max(high_freq) > 100
        except ImportError:
            # إذا لم يكن scipy مثبتاً، نستخدم بديلاً أبسط
            return np.std(pixels) > 50

    def check_metadata_anomalies(self, img):
        """فحص شذوذ البيانات الوصفية"""
        # هذه دالة افتراضية، تحتاج إلى تطوير
        # يمكن التحقق من:
        # - تناقض بين أبعاد الصورة وحجم الملف
        # - بيانات EXIF مشبوهة
        # - تواقيع ملفات غير متطابقة
        return False