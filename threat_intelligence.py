import requests
import hashlib
from datetime import datetime, timedelta

import logging

logging.basicConfig(level=logging.DEBUG)


# داخل دالة check_alienvault

class ThreatIntelligenceIntegration:
    def __init__(self, config):
        self.config = config
        self.cache = {}
        self.cache_expiry = timedelta(hours=1)

    def check_hash_reputation(self, file_hash):
        """فحص سمعة الملف باستخدام الهاش"""
        # التحقق من التخزين المؤقت أولاً
        if file_hash in self.cache:
            cached_data = self.cache[file_hash]
            if datetime.now() - cached_data['timestamp'] < self.cache_expiry:
                return cached_data['result']

        results = {}

        # التكامل مع VirusTotal
        if self.config.get('virustotal_api_key'):
            vt_result = self.check_virustotal(file_hash)
            results['virustotal'] = vt_result

        # التكامل مع AlienVault OTX
        if self.config.get('alienvault_api_key'):
            otx_result = self.check_alienvault(file_hash)
            results['alienvault'] = otx_result

        # حفظ النتائج في التخزين المؤقت
        self.cache[file_hash] = {
            'result': results,
            'timestamp': datetime.now()
        }

        return results

    def check_virustotal(self, file_hash):
        """التحقق من سمعة الملف على VirusTotal"""
        api_key = self.config.get('virustotal_api_key')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}

        url = f'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': file_hash}

        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                result = response.json()
                return {
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'permalink': result.get('permalink', ''),
                    'scan_date': result.get('scan_date', ''),
                    'response_code': result.get('response_code', 0)
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_alienvault(self, file_hash):
        """التحقق من سمعة الملف على AlienVault OTX"""
        api_key = self.config.get('alienvault_api_key')
        if not api_key:
            return {'error': 'AlienVault API key not configured'}

        url = f'https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general'
        headers = {'X-OTX-API-KEY': api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                return {
                    'pulse_count': result.get('pulse_info', {}).get('count', 0),
                    'related_ips': len(result.get('related', {}).get('url_list', [])),
                    'analysis': result.get('analysis', {})
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_domain_reputation(self, domain):
        """فحص سمعة النطاق"""
        results = {}

        # التكامل مع Google Safe Browsing
        if self.config.get('google_safe_browsing_api_key'):
            gsb_result = self.check_google_safe_browsing(domain)
            results['google_safe_browsing'] = gsb_result

        return results

    def check_google_safe_browsing(self, domain):
        """التحقق من سمعة النطاق على Google Safe Browsing"""
        api_key = self.config.get('google_safe_browsing_api_key')
        if not api_key:
            return {'error': 'Google Safe Browsing API key not configured'}

        url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        params = {'key': api_key}

        payload = {
            'client': {
                'clientId': 'cybershield',
                'clientVersion': '3.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': domain}]
            }
        }

        try:
            response = requests.post(url, params=params, json=payload)
            if response.status_code == 200:
                result = response.json()
                return {
                    'has_matches': 'matches' in result and len(result['matches']) > 0,
                    'matches': result.get('matches', [])
                }
            else:
                return {'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def update_threat_intelligence(self):
        """تحديث بيانات Threat Intelligence من مصادر خارجية"""
        # تنزيل قوائم التهديدات الحديثة
        threat_feeds = [
            'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            'https://reputation.alienvault.com/reputation.data'
        ]

        updated_data = {}

        for feed_url in threat_feeds:
            try:
                response = requests.get(feed_url, timeout=30)
                if response.status_code == 200:
                    feed_name = feed_url.split('/')[-1]
                    updated_data[feed_name] = response.text.split('\n')[:100]  # أول 100 سطر فقط
            except Exception as e:
                print(f"Error updating threat feed {feed_url}: {e}")

        return updated_data