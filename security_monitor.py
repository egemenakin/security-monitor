import os
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import json

# İzlenecek teknolojiler
TECHNOLOGIES = [
    'n8n',
    'prisma',
    'npm',
    'azure',
    'postgresql',
    'postgres',
    'mssql',
    'sql-server',
    'elasticsearch',
    'openai',
    'anthropic'
]

def get_github_advisories():
    """GitHub Security Advisories'den son 24 saatteki açıkları çek"""
    url = "https://api.github.com/advisories"
    headers = {"Accept": "application/vnd.github+json"}
    
    # Son 24 saat
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    
    vulnerabilities = []
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            advisories = response.json()
            
            for advisory in advisories:
                # Son 24 saatte yayınlananları kontrol et
                published = advisory.get('published_at', '')
                if published >= yesterday:
                    # Teknolojilerimizle eşleşiyor mu kontrol et
                    summary = (advisory.get('summary', '') + ' ' + 
                             advisory.get('description', '')).lower()
                    
                    for tech in TECHNOLOGIES:
                        if tech in summary:
                            vulnerabilities.append({
                                'source': 'GitHub Advisory',
                                'technology': tech.upper(),
                                'title': advisory.get('summary', 'N/A'),
                                'severity': advisory.get('severity', 'N/A'),
                                'cve': advisory.get('cve_id', 'N/A'),
                                'url': advisory.get('html_url', 'N/A'),
                                'published': advisory.get('published_at', 'N/A')
                            })
                            break
    except Exception as e:
        print(f"GitHub API hatası: {e}")
    
    return vulnerabilities

def get_nvd_vulnerabilities():
    """NVD (National Vulnerability Database) den son açıkları çek"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    vulnerabilities = []
    
    try:
        # Son 24 saat içinde değiştirilen CVE'ler
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000')
        
        params = {
            'lastModStartDate': yesterday,
            'resultsPerPage': 100
        }
        
        response = requests.get(url, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            cves = data.get('vulnerabilities', [])
            
            for item in cves:
                cve = item.get('cve', {})
                descriptions = cve.get('descriptions', [])
                description = descriptions[0].get('value', '') if descriptions else ''
                
                # Teknolojilerimizle eşleşiyor mu kontrol et
                description_lower = description.lower()
                for tech in TECHNOLOGIES:
                    if tech in description_lower:
                        metrics = cve.get('metrics', {})
                        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
                        severity = cvss_v3.get('cvssData', {}).get('baseSeverity', 'N/A')
                        
                        vulnerabilities.append({
                            'source': 'NVD',
                            'technology': tech.upper(),
                            'title': description[:200] + '...' if len(description) > 200 else description,
                            'severity': severity,
                            'cve': cve.get('id', 'N/A'),
                            'url': f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                            'published': cve.get('published', 'N/A')
                        })
                        break
    except Exception as e:
        print(f"NVD API hatası: {e}")
    
    return vulnerabilities

def send_daily_report(vulnerabilities):
    """Her gün rapor gönder - açık olsun olmasın"""
    sender = os.environ.get('EMAIL_SENDER')
    password = os.environ.get('EMAIL_PASSWORD')
    receiver = os.environ.get('EMAIL_RECEIVER')
    smtp_server = os.environ.get('SMTP_SERVER')
    
    if not all([sender, password, receiver, smtp_server]):
        print("Email bilgileri eksik!")
        return False
    
    # Email içeriği
    msg = MIMEMultipart('alternative')
    
    if len(vulnerabilities) > 0:
        msg['Subject'] = f'🔒 Güvenlik Bildirimi - {len(vulnerabilities)} Yeni Açık Bulundu'
        summary = f'<p><strong>{len(vulnerabilities)} yeni güvenlik açığı tespit edildi.</strong></p>'
        vuln_section = ''
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower() if vuln['severity'] != 'N/A' else 'low'
            vuln_section += f"""
                <div class="vulnerability {severity_class}">
                    <div>
                        <span class="tech">{vuln['technology']}</span>
                        <span class="severity severity-{severity_class}">{vuln['severity']}</span>
                    </div>
                    <h3>{vuln['title']}</h3>
                    <p><strong>CVE:</strong> {vuln['cve']}</p>
                    <p><strong>Kaynak:</strong> {vuln['source']}</p>
                    <p><strong>Yayın Tarihi:</strong> {vuln['published'][:10]}</p>
                    <p><a href="{vuln['url']}" target="_blank">Detaylı Bilgi →</a></p>
                </div>
            """
    else:
        msg['Subject'] = '✅ Güvenlik Raporu - Bugün Açık Bulunamadı'
        summary = '<p><strong>✅ Bugün yeni güvenlik açığı bulunamadı.</strong></p><p>İzlenen teknolojiler: NPM, Prisma, Azure, PostgreSQL, MSSQL, Elasticsearch, N8N, OpenAI, Anthropic</p>'
        vuln_section = ''
    
    msg['From'] = sender
    msg['To'] = receiver
    
    # HTML içerik
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .header {{ background-color: {'#d32f2f' if len(vulnerabilities) > 0 else '#4caf50'}; color: white; padding: 20px; }}
            .vulnerability {{ 
                border: 1px solid #ddd; 
                margin: 10px 0; 
                padding: 15px; 
                border-radius: 5px;
                background-color: #f9f9f9;
            }}
            .critical {{ border-left: 5px solid #d32f2f; }}
            .high {{ border-left: 5px solid #ff6f00; }}
            .medium {{ border-left: 5px solid #ffa000; }}
            .low {{ border-left: 5px solid #fbc02d; }}
            .tech {{ 
                display: inline-block;
                background-color: #1976d2;
                color: white;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 12px;
                margin-right: 5px;
            }}
            .severity {{ 
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: bold;
            }}
            .severity-critical {{ background-color: #d32f2f; color: white; }}
            .severity-high {{ background-color: #ff6f00; color: white; }}
            .severity-medium {{ background-color: #ffa000; color: white; }}
            .severity-low {{ background-color: #fbc02d; color: black; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>{'🔒 Günlük Güvenlik Raporu' if len(vulnerabilities) > 0 else '✅ Günlük Güvenlik Raporu'}</h2>
            <p>{datetime.now().strftime('%d.%m.%Y %H:%M')}</p>
        </div>
        <div style="padding: 20px;">
            {summary}
            {vuln_section}
        </div>
        <div style="padding: 20px; background-color: #f5f5f5; margin-top: 20px;">
            <p style="font-size: 12px; color: #666;">
                Bu rapor GitHub Actions tarafından otomatik olarak oluşturulmuştur.<br>
                Her gün saat 09:00'da (Türkiye saati) kontrol yapılır.
            </p>
        </div>
    </body>
    </html>
    """
    
    msg.attach(MIMEText(html_content, 'html'))
    
    # Email gönder
    try:
        with smtplib.SMTP(smtp_server, 587) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
        if len(vulnerabilities) > 0:
            print(f"✅ Email başarıyla gönderildi: {len(vulnerabilities)} açık")
        else:
            print(f"✅ Email başarıyla gönderildi: Bugün açık bulunamadı")
        return True
    except Exception as e:
        print(f"❌ Email gönderme hatası: {e}")
        return False

def main():
    print("🔍 Güvenlik açıkları taranıyor...")
    
    # Verileri topla
    all_vulnerabilities = []
    
    print("📡 GitHub Advisories kontrol ediliyor...")
    github_vulns = get_github_advisories()
    all_vulnerabilities.extend(github_vulns)
    print(f"   └─ {len(github_vulns)} açık bulundu")
    
    print("📡 NVD kontrol ediliyor...")
    nvd_vulns = get_nvd_vulnerabilities()
    all_vulnerabilities.extend(nvd_vulns)
    print(f"   └─ {len(nvd_vulns)} açık bulundu")
    
    # Sonuçları göster
    print(f"\n📊 Toplam {len(all_vulnerabilities)} güvenlik açığı bulundu")
    
    # Her durumda email gönder
    print("\n📧 Email gönderiliyor...")
    send_daily_report(all_vulnerabilities)
    
    # Sonuçları dosyaya kaydet (opsiyonel - loglama için)
    with open('last_check.json', 'w', encoding='utf-8') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'count': len(all_vulnerabilities),
            'vulnerabilities': all_vulnerabilities
        }, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
