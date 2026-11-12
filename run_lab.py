#!/usr/bin/env python3
"""Activity 1: actual Ethernet capture in isolated Linux network namespaces.

Requires an ephemeral Linux VM with administrative privileges. Never run against
production networks: all traffic is confined to the namespaces created here.
No packets or screenshots are fabricated by this script.
"""
import csv
import datetime
import hashlib
import http.server
import json
import os
import pwd
from pathlib import Path
import shlex
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import time
import urllib.parse

HERE=Path(__file__).resolve().parent
OUT=HERE/'evidencias'
LOG=OUT/'registos'
NS=['labcli','labrouter','labsrv']
CLIENT='10.77.10.10'
SERVER='10.77.20.20'
PASSWORD='LabIII_2026'
BODY='username=aluno&password='+PASSWORD

def run(args,namespace=None,timeout=20,check=True):
    actual=(['ip','netns','exec',namespace] if namespace else [])+list(args)
    p=subprocess.run(actual,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(shlex.join(actual)+'\n'+p.stdout+'\n'+p.stderr)
    return {'command':shlex.join(args),'namespace':namespace,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}

def command_log(name,args,namespace='labcli'):
    r=run(args,namespace,check=False)
    (LOG/(name+'.txt')).write_text('COMANDO EXECUTADO: '+r['command']+'\nAMBIENTE: '+str(namespace)+'\n\n'+r['stdout']+r['stderr']+'\nCODIGO DE SAIDA: '+str(r['returncode'])+'\n')
    return r

def child(args,ns,logname):
    f=(LOG/logname).open('w')
    p=subprocess.Popen(['ip','netns','exec',ns]+args,stdout=f,stderr=f)
    return p,f

class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def reply(self,b):
        self.send_response(200)
        self.send_header('Content-Type','text/plain; charset=utf-8')
        self.send_header('Content-Length',str(len(b)))
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        self.reply(b'Laboratorio III - servidor HTTP/HTTPS isolado.\n')
    def do_POST(self):
        data=self.rfile.read(int(self.headers.get('Content-Length','0')))
        self.reply(b'Credenciais ficticias recebidas para a experiencia.\n')

class Telnet(socketserver.BaseRequestHandler):
    def line(self):
        data=b''
        while not data.endswith(b'\n'):
            part=self.request.recv(1)
            if not part: break
            data+=part
        return data.strip()
    def handle(self):
        self.request.sendall(b'Laboratorio III - Telnet didactico\r\nlogin: ')
        name=self.line()
        self.request.sendall(b'Password: ')
        password=self.line()
        self.request.sendall(b'Conta ficticia recebida. Sessao de demonstracao.\r\n')

def services(kind):
    if kind=='telnet':
        socketserver.ThreadingTCPServer.allow_reuse_address=True
        socketserver.ThreadingTCPServer((SERVER,23),Telnet).serve_forever()
    else:
        s=http.server.ThreadingHTTPServer((SERVER,80 if kind=='http' else 443),HTTP)
        if kind=='https':
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(OUT/'privado/web.crt',OUT/'privado/web.key')
            s.socket=ctx.wrap_socket(s.socket,server_side=True)
        s.serve_forever()

def telnet_client():
    def receive(s,marker):
        data=b''
        while marker not in data:
            p=s.recv(4096)
            if not p: break
            data+=p
        sys.stdout.write(data.decode())
    with socket.create_connection((SERVER,23),timeout=3) as s:
        receive(s,b'login: ')
        s.sendall(b'aluno\r\n')
        print('aluno')
        receive(s,b'Password: ')
        s.sendall(PASSWORD.encode()+b'\r\n')
        print(PASSWORD)
        receive(s,b'demonstracao.\r\n')

def field(row,key,default=''):
    v=row.get('_source',{}).get('layers',{}).get(key,[])
    return v[0] if isinstance(v,list) and v else v or default

def analyze():
    pcap=OUT/'atividade1.pcap'
    fields=['frame.number','frame.time_epoch','frame.time_relative','frame.len','frame.cap_len','frame.protocols','eth.src','eth.dst','eth.type','ip.src','ip.dst','ip.ttl','ip.hdr_len','ip.len','ip.proto','tcp.srcport','tcp.dstport','tcp.stream','tcp.seq','tcp.ack','tcp.seq_raw','tcp.ack_raw','tcp.flags','tcp.flags.syn','tcp.flags.ack','tcp.hdr_len','tcp.len','tcp.payload','udp.srcport','udp.dstport','dns.qry.name','dns.flags.response','dns.a','arp.opcode','icmp.type','http.request.method','http.host','http.file_data','tls.handshake.type','tls.record.content_type','_ws.col.Protocol','_ws.col.Info']
    argv=['tshark','-n','-r',str(pcap),'-T','json']
    for f in fields: argv+=['-e',f]
    r=run(argv)
    (LOG/'pacotes_campos.json').write_text(r['stdout'])
    packets=json.loads(r['stdout'])
    http=next(p for p in packets if field(p,'http.request.method')=='POST')
    stream=field(http,'tcp.stream')
    same=[p for p in packets if field(p,'tcp.stream')==stream]
    handshake=same[:3]
    h=[]
    for p in handshake:
        h.append({k:field(p,k) for k in ['frame.number','frame.time_relative','frame.len','eth.src','eth.dst','ip.src','ip.dst','ip.ttl','ip.hdr_len','ip.len','tcp.srcport','tcp.dstport','tcp.seq','tcp.ack','tcp.seq_raw','tcp.ack_raw','tcp.flags','tcp.hdr_len','tcp.len']})
    assert len(h)==3 and [int(x['tcp.flags'],16) for x in h]==[2,18,16],h
    assert int(h[1]['tcp.ack_raw'])==(int(h[0]['tcp.seq_raw'])+1)%(2**32)
    assert int(h[2]['tcp.ack_raw'])==(int(h[1]['tcp.seq_raw'])+1)%(2**32)
    telnet=next(p for p in packets if field(p,'tcp.dstport')=='23' and PASSWORD.encode().hex() in field(p,'tcp.payload').replace(':',''))
    tls_packets=[p for p in packets if '443' in [field(p,'tcp.srcport'),field(p,'tcp.dstport')]]
    ssh_packets=[p for p in packets if '22' in [field(p,'tcp.srcport'),field(p,'tcp.dstport')]]
    def payloads(rows):
        return b''.join(bytes.fromhex(field(p,'tcp.payload').replace(':','')) for p in rows)
    tls_bytes=payloads(tls_packets)
    ssh_bytes=payloads(ssh_packets)
    http_follow=run(['tshark','-n','-r',str(pcap),'-q','-z','follow,tcp,ascii,'+stream])['stdout']
    telnet_stream=field(telnet,'tcp.stream')
    telnet_follow=run(['tshark','-n','-r',str(pcap),'-q','-z','follow,tcp,ascii,'+telnet_stream])['stdout']
    (LOG/'http_follow_stream.txt').write_text(http_follow)
    (LOG/'telnet_follow_stream.txt').write_text(telnet_follow)
    (LOG/'tcp_handshake.txt').write_text(run(['tshark','-n','-r',str(pcap),'-Y','tcp.stream == '+stream,'-T','fields','-e','frame.number','-e','ip.src','-e','tcp.srcport','-e','ip.dst','-e','tcp.dstport','-e','tcp.flags','-e','tcp.seq','-e','tcp.ack'])['stdout'])
    (LOG/'quadro_syn_detalhado.txt').write_text(run(['tshark','-n','-r',str(pcap),'-Y','frame.number == '+h[0]['frame.number'],'-V','-x'])['stdout'])
    (LOG/'resumo_protocolos.txt').write_text(run(['tshark','-n','-r',str(pcap),'-q','-z','io,phs'])['stdout'])
    (LOG/'capinfos.txt').write_text(run(['capinfos',str(pcap)])['stdout'])
    cols=['frame.number','frame.time_relative','eth.src','eth.dst','ip.src','ip.dst','ip.ttl','tcp.srcport','tcp.dstport','tcp.flags','tcp.seq','tcp.ack','_ws.col.Protocol','_ws.col.Info']
    with (LOG/'pacotes.csv').open('w') as f:
        w=csv.writer(f);w.writerow(cols)
        for p in packets:w.writerow([field(p,k) for k in cols])
    checks={
      'captura_ethernet':bool(h[0]['eth.src'] and h[0]['eth.dst']),
      'arp_request_reply':{field(p,'arp.opcode') for p in packets}>={'1','2'},
      'icmp_echo_request_reply':{field(p,'icmp.type') for p in packets}>={'0','8'},
      'dns_query_response':any(field(p,'dns.qry.name')=='intranet.orbion.test' and field(p,'dns.a')==SERVER for p in packets),
      'handshake_SYN_SYNACK_ACK':True,
      'http_password_visible':BODY in http_follow,
      'telnet_password_visible':PASSWORD in telnet_follow,
      'https_clienthello_observed':any('1' in p['_source']['layers'].get('tls.handshake.type',[]) for p in tls_packets),
      'https_password_not_plaintext':bool(tls_bytes) and PASSWORD.encode() not in tls_bytes and BODY.encode() not in tls_bytes,
      'ssh_banner_observed':b'SSH-2.0-' in ssh_bytes,
      'ssh_command_not_plaintext':b'SSH_COM_CHAVE_OK' not in ssh_bytes,
      'ssh_authenticated': 'SSH_COM_CHAVE_OK' in (LOG/'ssh.txt').read_text(),
    }
    summary={'environment':'VM Linux efemera GitHub Actions; tres namespaces de rede ligados por veth e routing IP. Captura real em Ethernet virtual do cliente.','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'client':CLIENT,'server':SERVER,'gateway':'10.77.10.1','packet_count':len(packets),'pcap_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest(),'http_stream':stream,'telnet_stream':telnet_stream,'handshake':h,'sample_http_frame':field(http,'frame.number'),'sample_telnet_frame':field(telnet,'frame.number'),'sample_tls_frame':field(tls_packets[0],'frame.number'),'sample_ssh_frame':field(ssh_packets[0],'frame.number'),'checks':checks,'all_checks_passed':all(checks.values())}
    (OUT/'analise.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    assert summary['all_checks_passed'],summary

def main():
    OUT.mkdir(exist_ok=True);LOG.mkdir(exist_ok=True);(OUT/'privado').mkdir(exist_ok=True)
    procs=[];cap=None
    try:
        for ns in NS:
            run(['ip','netns','add',ns]);run(['ip','link','set','lo','up'],ns)
        run(['ip','link','add','labc0','type','veth','peer','name','labr0'])
        run(['ip','link','add','labr1','type','veth','peer','name','labs0'])
        for iface,ns,new,addr,mac in [('labc0','labcli','eth0',CLIENT+'/24','02:00:00:10:00:10'),('labr0','labrouter','r0','10.77.10.1/24','02:00:00:10:00:01'),('labr1','labrouter','r1','10.77.20.1/24','02:00:00:20:00:01'),('labs0','labsrv','eth0',SERVER+'/24','02:00:00:20:00:20')]:
            run(['ip','link','set',iface,'netns',ns]);run(['ip','link','set',iface,'name',new],ns)
            run(['ip','link','set',new,'address',mac],ns);run(['ip','address','add',addr,'dev',new],ns);run(['ip','link','set',new,'up'],ns)
        run(['ip','route','add','default','via','10.77.10.1'],'labcli')
        run(['ip','route','add','default','via','10.77.20.1'],'labsrv')
        run(['sysctl','-qw','net.ipv4.ip_forward=1'],'labrouter')
        for ns in ['labcli','labsrv']:run(['ethtool','-K','eth0','tx','off','rx','off','tso','off','gso','off','gro','off'],ns,check=False)
        resolv=Path('/etc/netns/labcli');resolv.mkdir(parents=True,exist_ok=True);(resolv/'resolv.conf').write_text('nameserver '+SERVER+'\noptions timeout:1 attempts:1\n')
        user=os.environ.get('SUDO_USER','runner')
        run(['id',user])
        account=pwd.getpwnam(user)
        os.chown(OUT,account.pw_uid,account.pw_gid)
        priv=OUT/'privado'
        for name in ['host_key','client_key']:
            run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(priv/name)])
        authorized=priv/'authorized_keys'
        authorized.write_bytes((priv/'client_key.pub').read_bytes())
        run(['chown',user,str(authorized)]);authorized.chmod(0o600)
        Path('/run/sshd').mkdir(exist_ok=True)
        (priv/'sshd_config').write_text(f'Port 22\nListenAddress {SERVER}\nHostKey {priv}/host_key\nPidFile {priv}/sshd.pid\nAuthorizedKeysFile {authorized}\nStrictModes yes\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\nAllowUsers {user}\nAllowTcpForwarding no\nX11Forwarding no\nLogLevel VERBOSE\n')
        (priv/'known_hosts').write_text(SERVER+' '+(priv/'host_key.pub').read_text())
        run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-days','3','-nodes','-keyout',str(priv/'web.key'),'-out',str(priv/'web.crt'),'-subj','/CN=intranet.orbion.test/O=Laboratorio III','-addext','subjectAltName=DNS:intranet.orbion.test,DNS:www.orbion.test,IP:'+SERVER])
        for kind in ['http','https','telnet']:procs.append(child([sys.executable,str(Path(__file__).resolve()),'serve',kind],'labsrv',kind+'_server.log'))
        procs.append(child(['dnsmasq','--no-daemon','--no-resolv','--no-hosts','--bind-interfaces','--listen-address='+SERVER,'--local=/orbion.test/','--host-record=intranet.orbion.test,'+SERVER,'--cname=www.orbion.test,intranet.orbion.test'],'labsrv','dns_server.log'))
        procs.append(child(['/usr/sbin/sshd','-D','-e','-f',str(priv/'sshd_config')],'labsrv','ssh_server.log'))
        time.sleep(.7)
        assert all(p.poll() is None for p,f in procs),[(p.returncode,f.name) for p,f in procs]
        cap=child(['dumpcap','-i','eth0','-P','-f','arp or icmp or port 53 or tcp port 80 or tcp port 443 or tcp port 23 or tcp port 22','-w',str(OUT/'atividade1.pcap')],'labcli','dumpcap.log')
        time.sleep(.8)
        assert cap[0].poll() is None,(LOG/'dumpcap.log').read_text()
        commands={}
        commands['ping']=command_log('01_ping',['ping','-c','4',SERVER])
        commands['traceroute']=command_log('02_traceroute',['traceroute','-n','-I','-m','5','-w','1',SERVER])
        commands['arp']=command_log('03_arp',['arp','-n'])
        commands['nslookup']=command_log('04_nslookup',['nslookup','-type=A','intranet.orbion.test',SERVER])
        commands['alias']=command_log('04b_nslookup_alias',['nslookup','-type=A','www.orbion.test',SERVER])
        commands['http']=command_log('05_http',['curl','--noproxy','*','--max-time','5','-sv','--data',BODY,'http://intranet.orbion.test/login'])
        commands['https']=command_log('06_https',['curl','--noproxy','*','--max-time','5','-sv','--cacert',str(priv/'web.crt'),'--tlsv1.3','--tls-max','1.3','--data',BODY,'https://intranet.orbion.test/login'])
        commands['telnet']=command_log('07_telnet',[sys.executable,str(Path(__file__).resolve()),'telnet-client'])
        sshargs=['ssh','-F','/dev/null','-vv','-i',str(priv/'client_key'),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(priv/'known_hosts'),user+'@'+SERVER,'id; hostname; printf "SSH_COM_CHAVE_OK\\n"; sleep 4']
        shlog=(LOG/'ssh.txt').open('w')
        sshp=subprocess.Popen(['ip','netns','exec','labcli']+sshargs,stdout=shlog,stderr=shlog)
        time.sleep(1)
        commands['netstat']=command_log('08_netstat',['netstat','-antp'])
        sshcode=sshp.wait(timeout=10);shlog.close();assert sshcode==0,(LOG/'ssh.txt').read_text()
        time.sleep(.3)
        cap[0].send_signal(signal.SIGINT);cap[0].wait(timeout=5);cap[1].close();cap=None
        (OUT/'comandos.json').write_text(json.dumps(commands,ensure_ascii=False,indent=2))
        for key in ['ping','traceroute','nslookup','http','https','telnet','netstat']:assert commands[key]['returncode']==0,(key,commands[key])
        (LOG/'ambiente.txt').write_text(run(['uname','-a'])['stdout']+run(['wireshark','--version'])['stdout']+run(['ip','-br','address'],'labcli')['stdout']+run(['ip','route'],'labcli')['stdout'])
        analyze()
        print((OUT/'analise.json').read_text())
    finally:
        if cap:
            cap[0].send_signal(signal.SIGINT)
            with __import__('contextlib').suppress(Exception):cap[0].wait(timeout=3)
            cap[1].close()
        for p,f in procs:
            p.terminate()
            with __import__('contextlib').suppress(Exception):p.wait(timeout=3)
            f.close()
        for ns in NS:run(['ip','netns','del',ns],check=False)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='serve':services(sys.argv[2])
    elif len(sys.argv)>1 and sys.argv[1]=='telnet-client':telnet_client()
    else:main()
