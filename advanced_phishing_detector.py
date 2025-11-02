import re
import numpy as np
import pickle

try:
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense, LSTM, Embedding, Dropout, Conv1D, GlobalMaxPooling1D
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences

    TENSORFLOW_AVAILABLE = True
except ImportError:
    try:
        from keras.models import Sequential, load_model
        from keras.layers import Dense, LSTM, Embedding, Dropout, Conv1D, GlobalMaxPooling11D
        from keras.preprocessing.text import Tokenizer
        from keras.preprocessing.sequence import pad_sequences

        TENSORFLOW_AVAILABLE = True
    except ImportError:
        TENSORFLOW_AVAILABLE = False


class AdvancedPhishingDetector:
    def __init__(self, model_path=None, tokenizer_path=None):
        self.model = None
        self.tokenizer = None
        self.max_sequence_length = 100

        if model_path and tokenizer_path and TENSORFLOW_AVAILABLE:
            self.load_model(model_path, tokenizer_path)
        else:
            self.initialize_new_model()

    def initialize_new_model(self):
        """تهيئة نموذج جديد للكشف عن التصيد"""
        if not TENSORFLOW_AVAILABLE:
            return

        self.tokenizer = Tokenizer(num_words=10000, oov_token="<OOV>")

        # بناء نموذج LSTM/CNN متقدم
        self.model = Sequential([
            Embedding(10000, 128, input_length=self.max_sequence_length),
            Conv1D(128, 5, activation='relu'),
            GlobalMaxPooling1D(),
            LSTM(64, return_sequences=True),
            LSTM(32),
            Dense(64, activation='relu'),
            Dropout(0.5),
            Dense(1, activation='sigmoid')
        ])

        self.model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )

    def load_model(self, model_path, tokenizer_path):
        """تحميل نموذج مدرب ومرمز الكلمات"""
        try:
            self.model = load_model(model_path)
            with open(tokenizer_path, 'rb') as handle:
                self.tokenizer = pickle.load(handle)
        except Exception as e:
            print(f"Error loading model: {e}")
            self.initialize_new_model()

    def extract_advanced_features(self, text):
        """استخراج ميزات متقدمة من النص"""
        features = {}

        # 1. تحليل أنماط URLs
        url_patterns = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                  text)
        features['url_count'] = len(url_patterns)
        features['suspicious_urls'] = []

        for url in url_patterns:
            # الكشف عن أنماط URLs مشبوهة
            if re.search(r'(login|signin|verify|account|security|update|confirm)', url, re.IGNORECASE):
                if not re.search(r'(facebook|google|microsoft|apple|amazon|twitter)\.com', url, re.IGNORECASE):
                    features['suspicious_urls'].append(url)

        # 2. تحليل أنماط البريد الإلكتروني
        email_patterns = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        features['email_count'] = len(email_patterns)

        # 3. تحليل أنماط التصيد المعروفة
        phishing_keywords = [
            'urgent', 'immediately', 'verify', 'account', 'suspended', 'security',
            'update', 'confirm', 'password', 'login', 'credentials', 'bank',
            'payment', 'invoice', 'required', 'action', 'alert', 'notice',
            'دعوة عاجلة', 'تحديث عاجل', 'حساب', 'كلمة المرور', 'تأكيد',
            'تسجيل الدخول', 'أمن', 'تحذير', 'تنبيه', 'مطلوب'
        ]

        features['phishing_keywords'] = []
        for keyword in phishing_keywords:
            if keyword.lower() in text.lower():
                features['phishing_keywords'].append(keyword)

        # 4. تحليل التناقض في النطاق
        domain_mismatch = False
        if url_patterns and email_patterns:
            email_domains = set([email.split('@')[1] for email in email_patterns])
            url_domains = set()

            for url in url_patterns:
                domain = re.search(r'https?://([^/]+)', url)
                if domain:
                    url_domains.add(domain.group(1))

            if email_domains and url_domains and not email_domains.intersection(url_domains):
                domain_mismatch = True

        features['domain_mismatch'] = domain_mismatch

        return features

    def predict_phishing(self, text):
        """التنبؤ بما إذا كان النص يحتوي على تصيد"""
        if not text or len(text.strip()) == 0:
            return 0.0

        # استخراج الميزات المتقدمة
        advanced_features = self.extract_advanced_features(text)

        # استخدام النموذج للتنبؤ (إذا كان مدرباً)
        if self.tokenizer and self.model and TENSORFLOW_AVAILABLE:
            try:
                sequences = self.tokenizer.texts_to_sequences([text])
                padded = pad_sequences(sequences, maxlen=self.max_sequence_length)
                prediction = self.model.predict(padded, verbose=0)[0][0]
                return float(prediction)
            except Exception as e:
                print(f"Model prediction error: {e}")

        # التنبؤ الأساسي بناءً على الميزات المستخرجة
        base_score = 0.0

        # زيادة النقاط بناءً على الميزات المشبوهة
        if advanced_features['url_count'] > 0:
            base_score += 0.1

        if advanced_features['suspicious_urls']:
            base_score += 0.2 * len(advanced_features['suspicious_urls'])

        if advanced_features['phishing_keywords']:
            base_score += 0.1 * len(advanced_features['phishing_keywords'])

        if advanced_features['domain_mismatch']:
            base_score += 0.3

        return min(base_score, 1.0)