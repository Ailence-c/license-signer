# server.py - 支持日志记录与查询
import sys
import os
import json
import time
import socket
import csv
from datetime import datetime
from flask import Flask, request, jsonify, send_file

if getattr(sys, 'frozen', False):
    application_path = sys._MEIPASS
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, application_path)

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    print(f"导入加密模块失败: {e}")
    print("请安装: pip install cryptography")
    input("按任意键退出...")
    sys.exit(1)

app = Flask(__name__)

# 日志文件
LOG_FILE = os.path.join(application_path, 'license_log.csv')

# 初始化日志文件
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['订单号', '机器码', '授权签发日期', '授权到期日期', '授权文件内容', 'f+e+sig拼接值'])

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    return response

private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDXXg+5neRCmN44
XkrrFSjX/w3z3c1BsnT9PGcwLmAv1hiVwSluch+S74ijT1VHuX1EDeVklxY9g5nz
IsHVOfvlmyvN3Ox4QhDW9DCWzvkS1BMh9FCTKuKnq3KYinsK0nQaDJlqQtNBIVyY
mxwCp3LS4On3IceZVGzvArHhIQrTy88x+dCSKsvSAz5QxBUzREslNDrNKKDiFgC7
uSuCs8CctGmdNWS0WzDbxCr04msoN3X6OiI8osMuI085XFpHsOwyrzHeldvdIHgK
A3gr40SA6T2fdP++d3TfU1l1X2pYtcD4+PeCqhZ/4rvoiOJukerpaq++RK+J0PgX
WJDluzmPAgMBAAECggEADMqg63jlyFDVDgsHrxvEH8Qd24imesrzKOFQDawLeXvh
XO+qms07c9o3Rt/c5FQvjP24TLeukfvBho/fbF8zx2jmeqUvBFuELYg2ZJapc4VW
F5Ovv3XyHVxRA59h/HwQekWaTRXn/zvQiJ3Z1YyFhOHn8441kTVS/QUvdHwmbPrX
iBXiUk0s5jX/OSmX5tqnmpdxTnf7RbgyXe+vHfwR1JIzF7sxTzNDmQQW71NwjFsm
ApprwWq6TV4MFai8H5bIufttzUFEFipmGEO2JiFSee3skeN025kphP3BfMT+iYEV
2XzQE3sBXOapYcwzyAwsV+ItI1wiT4NFoUE1CWH/8QKBgQD2il0AvbPcQOM+YMDU
GNGZL+cZDNP1v6ARYHdmAUMciE6C2B9PhhePJV6lSVk/JywTKWKJIxFwgf4mniVd
oM5Ed4cOwtdcGgoTmb6H+i+m7qkg4NdBIXmf1IPSbzF+R3GCjZ3zeegKXXAHeedT
szd0Xq0RVzr+RPzx5r9uMHb2kQKBgQDfoYBwdHG6GvsChl6JDnEWK/N27RELLMFd
WAfs7BHZaGoASs5DD4NXPsk6mh2eDvD9OKkkgTflycAcKaVsw6HBOzqQ9f04A6Ok
0G8iQO2/Okr/McX6ZG4fWXNSo38XijR4ICPEUbBVVwcOxDjRThVqE0XSY6pzLLgQ
SIxbhnh+HwKBgQDx1ZuRBISPgt7l60Z7RrUjDMgl3F12bDf5k6TLXGWWcWaCFrnv
6drmQYProl13A1fKnAfZ+Zo7wGerPentQ7XRl2XV5u4VnD1SKLeq7pEbsHQamjLL
4qhJTc7Y9tWXx0DjDUNo96XTtQAVdVCi2+ODtPMTVXu6u7VbHDufPM8U4QKBgDXo
QoPZLgkEs/lZ1rQHLS+BDMFgSDl/YmVT8SUliu/zgYnsfmgf9zMyyWM8/2K4i1Mf
M3a/R3A2//5J87ySNA3Wbzm+cnnsNqhmLkP9jtIIBUgbAXRofTtFXs1O6DYOdLN4
W+bZIj6QKf1fQ6sAvZzCZJRgvhfhccVLF7qAYc9VAoGBAMv8pKYeq1TssWZ+s1gV
RpTv9Mj317ryo/KAqDkEastih+8Dy/xpivCO6NEJ+WKAE6pNVF3WeqOCZDB+IAle
kE17JKWzkaGaO75tF9tCwUzLlLgbxiAmjOvb0MjM0P84kgGLLijnRGt+sk7n9uWz
//ajd5J0X9gaLHosS7I/uhYu
-----END PRIVATE KEY-----"""

try:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    print("✅ 私钥加载成功")
except Exception as e:
    print(f"❌ 私钥加载失败: {e}")
    input("按任意键退出...")
    sys.exit(1)

def log_license(order_id, fingerprint, expiration, license_content, concatenated):
    try:
        issued = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expires = datetime.fromtimestamp(expiration).strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([order_id or '', fingerprint, issued, expires, license_content, concatenated])
    except Exception as e:
        print(f"⚠️ 写入日志失败: {e}")

@app.route('/sign', methods=['POST', 'OPTIONS'])
def sign():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': '请求体必须是JSON格式'}), 400
        fingerprint = data.get('fingerprint', '').strip()
        days = int(data.get('days', 365))
        order_id = data.get('orderId', '').strip()
        if not fingerprint:
            return jsonify({'success': False, 'error': '缺少机器码参数'}), 400
        if not all(c in '0123456789abcdefABCDEF' for c in fingerprint) or len(fingerprint) != 64:
            return jsonify({'success': False, 'error': '机器码必须是64位十六进制字符串'}), 400
        exp = int(time.time()) + days * 86400
        msg = json.dumps({"f": fingerprint, "e": exp}, separators=(',', ':')).encode()
        signature = private_key.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        license_content = json.dumps({"f": fingerprint, "e": exp, "sig": signature.hex()}, separators=(',', ':'))
        concatenated = fingerprint + str(exp) + signature.hex()
        log_license(order_id, fingerprint, exp, license_content, concatenated)
        return jsonify({'success': True, 'signature': signature.hex(), 'expiration': exp})
    except ValueError as e:
        return jsonify({'success': False, 'error': f'参数错误: {str(e)}'}), 400
    except Exception as e:
        print(f"签名错误: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/batch_sign', methods=['POST', 'OPTIONS'])
def batch_sign():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': '请求体必须是JSON格式'}), 400
        fingerprints = data.get('fingerprints', [])
        days = int(data.get('days', 365))
        order_id = data.get('orderId', '').strip()
        if not isinstance(fingerprints, list) or len(fingerprints) == 0:
            return jsonify({'success': False, 'error': '参数fingerprints必须是非空列表'}), 400
        valid_fingerprints = []
        for fp in fingerprints:
            fp_str = str(fp).strip()
            if all(c in '0123456789abcdefABCDEF' for c in fp_str) and len(fp_str) == 64:
                valid_fingerprints.append(fp_str)
        if len(valid_fingerprints) == 0:
            return jsonify({'success': False, 'error': '没有有效的机器码（必须是64位十六进制）'}), 400
        results = []
        exp = int(time.time()) + days * 86400
        for fingerprint in valid_fingerprints:
            try:
                msg = json.dumps({"f": fingerprint, "e": exp}, separators=(',', ':')).encode()
                signature = private_key.sign(
                    msg,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                license_content = json.dumps({"f": fingerprint, "e": exp, "sig": signature.hex()}, separators=(',', ':'))
                concatenated = fingerprint + str(exp) + signature.hex()
                log_license(order_id, fingerprint, exp, license_content, concatenated)
                results.append({'fingerprint': fingerprint, 'signature': signature.hex(), 'expiration': exp})
            except Exception as e:
                print(f"机器码 {fingerprint} 签名失败: {e}")
                continue
        return jsonify({'success': True, 'results': results, 'total': len(valid_fingerprints), 'succeeded': len(results)})
    except ValueError as e:
        return jsonify({'success': False, 'error': f'参数错误: {str(e)}'}), 400
    except Exception as e:
        print(f"批量签名错误: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                logs.append(row)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    return jsonify({'success': True, 'logs': logs})

@app.route('/download_logs', methods=['GET'])
def download_logs():
    try:
        return send_file(LOG_FILE, as_attachment=True, download_name='license_log.csv')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'license-signing-server', 'version': '2.1.0', 'timestamp': int(time.time())})

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'running',
        'private_key_loaded': True,
        'server_time': time.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/')
def home():
    return '''
    <h2>授权签名服务器 v2.1.0</h2>
    <p>✅ 支持：/sign、/batch_sign、/logs、/download_logs</p>
    '''

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    port = 5000
    local_ip = get_local_ip()
    print("=" * 60)
    print("✅ 授权签名服务器 v2.1.0 启动成功")
    print(f"🌐 日志页面: http://{local_ip}:{port}/logs")
    print(f"📥 下载日志: http://{local_ip}:{port}/download_logs")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)