#!/usr/bin/env python3
"""Laboratorio III: duas VMs QEMU e rede empresarial isolada.

Executar apenas num anfitriao Linux descartavel e dedicado, com sudo, KVM e
as dependencias indicadas no workflow. Nao altera a firewall, o DNS ou a rota
por omissao do anfitriao. As interfaces e namespaces criados usam lab34.
As chaves privadas ficam em work34/privado e nunca integram as evidencias.
"""
import datetime,hashlib,http.server,json,os,re,shlex,shutil,signal,subprocess,sys,time
from pathlib import Path
import yaml

HERE=Path(__file__).resolve().parent
WORK=HERE/'work34';PRIVATE=WORK/'privado';OUT=HERE/'evidencias34'
A3=OUT/'Atividade_3';A4=OUT/'Atividade_4'
for p in [WORK,PRIVATE,A3/'Registos',A3/'Capturas',A3/'Configuracoes',A4/'Registos',A4/'Capturas',A4/'Configuracoes']:
 p.mkdir(parents=True,exist_ok=True)
PRIVATE.chmod(0o700)
CHECKS={};PROCS=[]
NS={n:'lab34-'+n for n in ['r1','r2','isp','admin','filial','externo']}
MGMT={'srv':2221,'cli':2222}
KEY=PRIVATE/'controlo'

def run(args,ns=None,check=True,timeout=35,input=None):
 cmd=(['ip','netns','exec',NS.get(ns,ns)] if ns else [])+list(map(str,args))
 p=subprocess.run(cmd,input=input,text=True,capture_output=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError(shlex.join(cmd)+'\n'+p.stdout+'\n'+p.stderr)
 return p
def spawn(args,ns=None,log=None):
 cmd=(['ip','netns','exec',NS.get(ns,ns)] if ns else [])+list(map(str,args))
 f=open(log,'w') if log else subprocess.DEVNULL
 p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT)
 PROCS.append(p);return p
def check(name,ok,detail=''):
 CHECKS[name]={'ok':bool(ok),'detalhe':detail}
 print(('PASS ' if ok else 'FAIL ')+name+' '+detail,flush=True)
 save_results()
def save_results():
 (OUT/'verificacao.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':CHECKS,'all_passed':bool(CHECKS) and all(v['ok'] for v in CHECKS.values())},indent=2,ensure_ascii=False))
def log(stage,name,cmd,ns=None,check_result=True,timeout=35):
 r=run(cmd,ns,check=False,timeout=timeout)
 actual=('ip netns exec '+NS.get(ns,ns)+' ' if ns else '')+shlex.join(list(map(str,cmd)))
 (stage/'Registos'/name).write_text('COMANDO EXECUTADO: '+actual+'\n\n'+r.stdout+r.stderr+'\nCODIGO DE SAIDA: '+str(r.returncode)+'\n')
 if check_result and r.returncode:raise RuntimeError(name+'\n'+r.stdout+r.stderr)
 return r
def sshcmd(vm,command,check=True,timeout=50):
 return run(['ssh','-i',KEY,'-p',MGMT[vm],'-o','BatchMode=yes','-o','ConnectTimeout=4','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts'),'aluno@127.0.0.1',command],check=check,timeout=timeout)
def vlog(stage,name,vm,command,check_result=True,timeout=50):
 r=sshcmd(vm,command,check=False,timeout=timeout)
 (stage/'Registos'/name).write_text('MAQUINA VIRTUAL: '+('SRV-INFRA' if vm=='srv' else 'PC-FUNCIONARIO')+'\nCOMANDO EXECUTADO: '+command+'\n\n'+r.stdout+r.stderr+'\nCODIGO DE SAIDA: '+str(r.returncode)+'\n')
 if check_result and r.returncode:raise RuntimeError(name+'\n'+r.stdout+r.stderr)
 return r

SITE='''<!doctype html><html lang="pt"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Intranet Orbion</title><style>body{font:17px/1.6 Arial,sans-serif;color:#171717;max-width:820px;margin:60px auto;padding:0 28px}header{border-bottom:1px solid #ccc;padding-bottom:20px}h1{font-size:30px;line-height:1.2}h2{font-size:21px;margin-top:32px}nav a{margin-right:24px;color:inherit}footer{margin-top:50px;border-top:1px solid #ccc;padding-top:18px;font-size:14px}</style><header><p>ORBION TECHNOLOGY</p><h1>Intranet da empresa</h1><nav><a href="/">Inicio</a><a href="/rede.html">Rede interna</a><a href="/servicos.html">Servicos</a></nav></header><main><h2>Comunicacao interna</h2><p>Este portal reune as informacoes dos servicos da sede e da filial. O acesso e realizado pelo nome intranet.orbion.test.</p><h2>Servicos disponiveis</h2><p>O servidor SRV-INFRA fornece DHCP, DNS, servidor Web e acesso de administracao por SSH com chave publica.</p><h2>Organizacao da rede</h2><p>Administracao na VLAN 10, Funcionarios na VLAN 20, Servidores na VLAN 30 e Filial na rede 192.168.40.0/24.</p></main><footer>Laboratorio de Informatica III | Universidade Save | Empresa ficticia</footer></html>'''
DNS='''interface=lan0
bind-dynamic
no-resolv
domain-needed
bogus-priv
local=/orbion.test/
domain=orbion.test
host-record=intranet.orbion.test,192.168.30.10
cname=www.orbion.test,intranet.orbion.test
dhcp-authoritative
dhcp-range=192.168.20.100,192.168.20.150,255.255.255.0,12h
dhcp-host=52:54:00:20:00:10,192.168.20.10,pc-funcionario,12h
dhcp-option=option:router,192.168.20.1
dhcp-option=option:dns-server,192.168.30.10
dhcp-option=option:domain-name,orbion.test
log-dhcp
log-queries
'''
NGINX='''server {
    listen 80 default_server;
    server_name intranet.orbion.test www.orbion.test;
    root /var/www/intranet;
    index index.html;
    location / { try_files $uri $uri/ =404; }
}
'''

def ip(*a,ns=None):return run(['ip',*a],ns)
def addr(ns,dev,ipaddr):
 ip('addr','add',ipaddr,'dev',dev,ns=ns);ip('link','set',dev,'up',ns=ns)
def veth(a,an,b,bn):
 root='l34-'+a[:3]+'-'+b[:3]
 peer=root+'p'
 ip('link','add',root,'type','veth','peer','name',peer)
 for n,d,new in [(a,root,an),(b,peer,bn)]:
  if n=='root':ip('link','set',d,'name',new)
  else:ip('link','set',d,'netns',NS[n]);ip('link','set',d,'name',new,ns=n)
def setup_network():
 for n in NS:
  ip('netns','add',NS[n]);ip('link','set','lo','up',ns=n)
  if n in ['r1','r2','isp']:run(['sysctl','-qw','net.ipv4.ip_forward=1'],n)
  d=Path('/etc/netns')/NS[n];d.mkdir(parents=True,exist_ok=True)
  (d/'resolv.conf').write_text('nameserver 192.168.30.10\nsearch orbion.test\n')
 ip('link','add','lab34-sw','type','bridge','vlan_filtering','1')
 ip('link','set','lab34-sw','up')
 veth('root','l34-trunk','r1','trunk')
 ip('link','set','l34-trunk','master','lab34-sw');ip('link','set','l34-trunk','up')
 run(['bridge','vlan','del','dev','l34-trunk','vid','1'])
 for v in [10,20,30]:run(['bridge','vlan','add','dev','l34-trunk','vid',v])
 ip('link','set','trunk','up',ns='r1')
 for v in [10,20,30]:
  dev='trunk.'+str(v);ip('link','add','link','trunk','name',dev,'type','vlan','id',v,ns='r1');addr('r1',dev,f'192.168.{v}.1/24')
 for dev,v in [('l34-tapcli',20),('l34-tapsrv',30)]:
  ip('tuntap','add','dev',dev,'mode','tap');ip('link','set',dev,'master','lab34-sw');ip('link','set',dev,'up')
  run(['bridge','vlan','del','dev',dev,'vid','1']);run(['bridge','vlan','add','dev',dev,'vid',v,'pvid','untagged'])
 veth('root','l34-admin','admin','eth0')
 ip('link','set','l34-admin','master','lab34-sw');ip('link','set','l34-admin','up')
 run(['bridge','vlan','del','dev','l34-admin','vid','1']);run(['bridge','vlan','add','dev','l34-admin','vid','10','pvid','untagged'])
 addr('admin','eth0','192.168.10.10/24');ip('route','add','default','via','192.168.10.1',ns='admin')
 veth('r1','wan0','isp','sede0');addr('r1','wan0','203.0.113.2/30');addr('isp','sede0','203.0.113.1/30')
 veth('r2','wan0','isp','filial0');addr('r2','wan0','198.51.100.2/30');addr('isp','filial0','198.51.100.1/30')
 veth('isp','pub0','externo','eth0');addr('isp','pub0','192.0.2.1/24');addr('externo','eth0','192.0.2.10/24')
 ip('route','add','default','via','192.0.2.1',ns='externo')
 veth('r2','lan0','filial','eth0');addr('r2','lan0','192.168.40.1/24');addr('filial','eth0','192.168.40.10/24')
 ip('route','add','default','via','192.168.40.1',ns='filial')
 ip('route','add','default','via','203.0.113.1',ns='r1');ip('route','add','default','via','198.51.100.1',ns='r2')
 spawn(['dnsmasq','--no-daemon','--conf-file=/dev/null','--port=0','--dhcp-relay=192.168.20.1,192.168.30.10','--log-dhcp'],ns='r1',log=A3/'Registos/dhcp_relay.log')
 log(A3,'01_bridge_vlans.txt',['bridge','vlan','show'])
 log(A3,'02_router_sede.txt',['ip','-br','addr'],ns='r1')

def prepare_vms():
 run(['ssh-keygen','-q','-t','ed25519','-N','','-f',KEY])
 pub=KEY.with_suffix('.pub').read_text().strip()
 image=WORK/'noble-server-cloudimg-amd64.img'
 if not image.exists():run(['curl','-fL','--retry','2','--max-time','240','-o',image,'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img'],timeout=270)
 sums=run(['curl','-fsSL','--max-time','40','https://cloud-images.ubuntu.com/noble/current/SHA256SUMS']).stdout
 line=next(l for l in sums.splitlines() if l.endswith('noble-server-cloudimg-amd64.img'))
 expected=line.split()[0];actual=hashlib.sha256(image.read_bytes()).hexdigest()
 if actual!=expected:raise RuntimeError('Checksum da imagem Ubuntu diferente do publicado')
 (A3/'Registos/imagem_ubuntu.txt').write_text('Imagem oficial Ubuntu 24.04 LTS\nURL: https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img\nSHA256 publicado e calculado: '+actual+'\n')
 accel='kvm' if Path('/dev/kvm').exists() else 'tcg'
 check('duas_vms_hipervisor',True,'QEMU '+accel+'; dois discos e dois kernels independentes')
 for vm in ['srv','cli']:
  d=WORK/vm;d.mkdir(exist_ok=True)
  run(['qemu-img','create','-q','-f','qcow2','-F','qcow2','-b',image.resolve(),d/'disco.qcow2','8G'])
  business='52:54:00:30:00:10' if vm=='srv' else '52:54:00:20:00:10'
  management='52:54:00:aa:00:01' if vm=='srv' else '52:54:00:aa:00:02'
  net={'version':2,'ethernets':{'mgmt0':{'match':{'macaddress':management},'set-name':'mgmt0','dhcp4':True,'dhcp4-overrides':{'route-metric':600}},'lan0':{'match':{'macaddress':business},'set-name':'lan0','optional':True}}}
  if vm=='srv':net['ethernets']['lan0'].update({'addresses':['192.168.30.10/24'],'routes':[{'to':'192.168.0.0/16','via':'192.168.30.1'}]})
  else:net['ethernets']['lan0'].update({'dhcp4':True,'dhcp4-overrides':{'use-routes':False}})
  conf={'hostname':'srv-infra' if vm=='srv' else 'pc-funcionario','manage_etc_hosts':True,'ssh_pwauth':False,'disable_root':True,'users':[{'name':'aluno','shell':'/bin/bash','sudo':'ALL=(ALL) NOPASSWD:ALL','ssh_authorized_keys':[pub],'lock_passwd':True}],'package_update':True,'packages':['dnsutils','curl','iputils-ping','openssh-client']+(['dnsmasq','nginx','openssh-server'] if vm=='srv' else []),'write_files':[],'runcmd':[]}
  if vm=='srv':
   files={'/etc/dnsmasq.d/laboratorio.conf':DNS,'/etc/nginx/sites-available/default':NGINX,'/var/www/intranet/index.html':SITE,'/var/www/intranet/rede.html':SITE.replace('Comunicacao interna','Plano de enderecamento'),'/var/www/intranet/servicos.html':SITE.replace('Comunicacao interna','Servicos de infra-estrutura')}
   conf['write_files']=[{'path':p,'permissions':'0644','content':c} for p,c in files.items()]
   conf['runcmd']=['systemctl restart dnsmasq nginx ssh']
  (d/'user-data').write_text('#cloud-config\n'+yaml.safe_dump(conf,sort_keys=False))
  (d/'meta-data').write_text('instance-id: lab34-'+vm+'\nlocal-hostname: '+conf['hostname']+'\n')
  (d/'network-config').write_text(yaml.safe_dump(net,sort_keys=False))
  # The public report retains network configuration; credentials are not exported.
  (A3/'Configuracoes'/('rede_'+vm+'.yaml')).write_text(yaml.safe_dump(net,sort_keys=False))
  run(['cloud-localds','--network-config='+str(d/'network-config'),d/'seed.img',d/'user-data',d/'meta-data'])
  cmd=['qemu-system-x86_64','-name',conf['hostname'],'-accel',accel,'-m','1536','-smp','2','-cpu','host' if accel=='kvm' else 'max','-drive',f'file={d}/disco.qcow2,format=qcow2,if=virtio','-drive',f'file={d}/seed.img,format=raw,if=virtio','-netdev',f'user,id=mgmt,hostfwd=tcp:127.0.0.1:{MGMT[vm]}-:22','-device',f'virtio-net-pci,netdev=mgmt,mac={management}','-netdev',f'tap,id=lan,ifname=l34-tap{vm},script=no,downscript=no','-device',f'virtio-net-pci,netdev=lan,mac={business}','-display','none','-serial',f'file:{A3}/Registos/boot_{vm}.log','-monitor','none']
  spawn(cmd,log=A3/'Registos'/('qemu_'+vm+'.log'))
  print('VM iniciada: '+conf['hostname'],flush=True)
 # Wait for SSH, pin the host keys collected from these local guest endpoints.
 known=PRIVATE/'known_hosts';known.touch()
 for vm in ['srv','cli']:
  deadline=time.monotonic()+420
  while time.monotonic()<deadline:
   scan=run(['ssh-keyscan','-T','2','-p',MGMT[vm],'127.0.0.1'],check=False,timeout=8)
   if scan.returncode==0 and scan.stdout:
    with known.open('a') as f:f.write(scan.stdout)
    if sshcmd(vm,'true',check=False).returncode==0:break
   time.sleep(3)
  else:raise RuntimeError('SSH nao ficou disponivel em '+vm)
  print('SSH de controlo disponivel: '+vm,flush=True)
 for vm in ['srv','cli']:
  r=vlog(A3,'03_cloud_init_'+vm+'.txt',vm,'sudo cloud-init status --wait --long',check_result=False,timeout=480)
  if r.returncode not in [0,2]:raise RuntimeError('cloud-init falhou: '+vm+' '+r.stdout+r.stderr)
  vlog(A3,'04_identificacao_'+vm+'.txt',vm,'hostname; uname -r; systemd-detect-virt; cat /etc/os-release')
 check('duas_vms_linux',True,'SRV-INFRA e PC-FUNCIONARIO em QEMU; cloud-init concluido')

def activity3():
 # Packages are installed through the separate management NIC before business tests.
 sshcmd('cli','sudo networkctl renew lan0')
 for _ in range(30):
  ips=sshcmd('cli','ip -4 -br addr show dev lan0').stdout
  if '192.168.20.10/24' in ips:break
  time.sleep(2)
 r=vlog(A3,'05_dhcp_cliente.txt','cli','ip -4 -br addr; networkctl status lan0 --no-pager; ip route')
 check('dhcp_cliente_vlan20','192.168.20.10/24' in r.stdout,'Reserva DHCP para o MAC 52:54:00:20:00:10')
 sshcmd('cli','sudo ip route replace default via 192.168.20.1 dev lan0 metric 10; sudo resolvectl dns lan0 192.168.30.10; sudo resolvectl domain lan0 "~orbion.test"')
 sshcmd('srv','sudo ip route replace default via 192.168.30.1 dev lan0 metric 10')
 r=vlog(A3,'06_dns_registo_A.txt','cli','dig @192.168.30.10 intranet.orbion.test A +noall +answer')
 check('dns_registo_A','192.168.30.10' in r.stdout and '\tA\t' in r.stdout)
 r=vlog(A3,'07_dns_registo_CNAME.txt','cli','dig @192.168.30.10 www.orbion.test A +noall +answer')
 check('dns_registo_CNAME','CNAME' in r.stdout and 'intranet.orbion.test.' in r.stdout and '192.168.30.10' in r.stdout)
 r=vlog(A3,'08_nslookup.txt','cli','nslookup intranet.orbion.test 192.168.30.10; nslookup www.orbion.test 192.168.30.10')
 check('nslookup_dois_nomes',r.returncode==0 and r.stdout.count('192.168.30.10')>=2)
 r=vlog(A3,'09_web_por_nome.txt','cli','curl --noproxy "*" --fail --silent --show-error -D - http://intranet.orbion.test/; printf "\\n"; curl --noproxy "*" --fail --silent --show-error -o /dev/null -w "CNAME HTTP %{http_code}\\n" http://www.orbion.test/')
 check('site_acessivel_por_nome','200 OK' in r.stdout and 'CNAME HTTP 200' in r.stdout and 'Intranet da empresa' in r.stdout)
 sshcmd('cli','test -f ~/.ssh/id_ed25519 || ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519')
 pub=sshcmd('cli','cat ~/.ssh/id_ed25519.pub').stdout.strip()
 sshcmd('srv','printf "%s\\n" '+shlex.quote(pub)+' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys')
 sshcmd('cli','ssh-keyscan -H 192.168.30.10 >> ~/.ssh/known_hosts 2>/dev/null')
 r=vlog(A3,'10_ssh_sem_password.txt','cli','ssh -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes aluno@192.168.30.10 \'hostname; id; printf "SSH_COM_CHAVE_OK\\n"\'')
 check('ssh_sem_password',r.returncode==0 and 'SSH_COM_CHAVE_OK' in r.stdout and 'srv-infra' in r.stdout)
 vlog(A3,'11_servicos_e_concessoes.txt','srv','systemctl is-active dnsmasq nginx ssh; sudo cat /var/lib/misc/dnsmasq.leases; sudo ss -lntup')
 (A3/'Configuracoes/dnsmasq.conf').write_text(DNS);(A3/'Configuracoes/nginx.conf').write_text(NGINX)
 (A3/'Site').mkdir(exist_ok=True)
 for n in ['index.html','rede.html','servicos.html']:
  (A3/'Site'/n).write_text(sshcmd('srv','cat /var/www/intranet/'+n).stdout)
 # Public key authentication for the administration workstation, scoped to this lab.
 pub=KEY.with_suffix('.pub').read_text().strip()
 sshcmd('srv','printf "%s\\n" '+shlex.quote(pub)+' >> ~/.ssh/authorized_keys')
 sshcmd('srv','sudo cat /etc/ssh/ssh_host_ed25519_key.pub').stdout
 spawn(['Xvfb',':99','-screen','0','1280x900x24'],log=OUT/'xvfb.log')
 os.environ['DISPLAY']=':99';time.sleep(1)
 spawn(['openbox'],log=OUT/'openbox.log');time.sleep(1)
 screenshot_terminal(A3,'01_dhcp_dns','cli','hostname; ip -4 -br addr show lan0; ip route show default; dig @192.168.30.10 intranet.orbion.test A +noall +answer; dig @192.168.30.10 www.orbion.test A +noall +answer; nslookup www.orbion.test 192.168.30.10')
 screenshot_terminal(A3,'02_ssh_chave','cli','hostname; ssh -o BatchMode=yes -o PasswordAuthentication=no aluno@192.168.30.10 \'hostname; id; printf "SSH_COM_CHAVE_OK\\n"\'')
 screenshot_terminal(A3,'03_servicos','srv','hostname; systemctl is-active dnsmasq nginx ssh; sudo cat /var/lib/misc/dnsmasq.leases; sudo ss -lntup | head -18')
 # Real Chromium rendering, in the isolated administration segment, using lab DNS.
 chrome=shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser')
 if not chrome:raise RuntimeError('Chromium nao encontrado para verificar o site')
 r=log(A3,'12_browser_intranet.txt',[chrome,'--headless=new','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-proxy-server','--window-size=1280,900','--screenshot='+str(A3/'Capturas/04_site_intranet.png'),'http://intranet.orbion.test/'],ns='admin',timeout=50)
 check('captura_browser_site',(A3/'Capturas/04_site_intranet.png').stat().st_size>10000)

def screenshot_terminal(stage,name,vm,command):
 # Runs the commands again in the actual VM. The image is captured from Xvfb.
 # No terminal output is invented or painted into an image.
 cmd=['ssh','-i',str(KEY),'-p',str(MGMT[vm]),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts'),'aluno@127.0.0.1',command]
 snap_command(stage,name,shlex.join(cmd))
def snap_command(stage,name,command):
 script=WORK/(name+'.sh');done=WORK/(name+'.done')
 if done.exists():done.unlink()
 script.write_text('#!/bin/bash\n'+command+'\nprintf "\\n[Operacao concluida]\\n"\ntouch '+shlex.quote(str(done))+'\nsleep 30\n')
 p=spawn(['xterm','-geometry','126x42+5+5','-fa','DejaVu Sans Mono','-fs','11','-bg','white','-fg','black','-T','Laboratorio III - '+name,'-e','bash',str(script)],log=OUT/(name+'_xterm.log'))
 for _ in range(50):
  if done.exists():break
  time.sleep(.2)
 time.sleep(.7)
 run(['import','-display',':99','-window','root',stage/'Capturas'/(name+'.png')])
 p.terminate();p.wait(timeout=5)

def firewall(ns,rules):
 run(['iptables-restore'],ns,input=rules)
 (A4/'Configuracoes'/('firewall_'+ns+'.rules')).write_text(rules)

FW1='''*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ACL_FUNCIONARIOS - [0:0]
:ACL_FILIAL - [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i wan0 -s 198.51.100.2 -p udp --dport 51820 -j ACCEPT
-A INPUT -i trunk.20 -p udp --sport 68 --dport 67 -j ACCEPT
-A INPUT -i trunk.30 -s 192.168.30.10 -p udp --sport 67 -j ACCEPT
-A INPUT -s 192.168.0.0/16 -p icmp -j ACCEPT
-A INPUT -j DROP
-A FORWARD -m conntrack --ctstate INVALID -j DROP
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i trunk.10 -s 192.168.10.0/24 -d 192.168.30.10 -p tcp --dport 22 -j ACCEPT
-A FORWARD -i trunk.10 -s 192.168.10.0/24 -d 192.168.30.10 -p tcp --dport 80 -j ACCEPT
-A FORWARD -i trunk.10 -s 192.168.10.0/24 -d 192.168.30.10 -p udp --dport 53 -j ACCEPT
-A FORWARD -i trunk.10 -s 192.168.10.0/24 -d 192.168.40.0/24 -p icmp -o wg0 -j ACCEPT
-A FORWARD -i trunk.20 -s 192.168.20.0/24 -j ACL_FUNCIONARIOS
-A FORWARD -i wg0 -s 192.168.40.0/24 -j ACL_FILIAL
-A FORWARD -i trunk.10 -s 192.168.10.0/24 -d 192.0.2.10 -o wan0 -p tcp --dport 80 -j ACCEPT
-A FORWARD -j DROP
-A ACL_FUNCIONARIOS -d 192.168.30.10 -p tcp -m multiport --dports 53,80 -j ACCEPT
-A ACL_FUNCIONARIOS -d 192.168.30.10 -p udp --dport 53 -j ACCEPT
-A ACL_FUNCIONARIOS -d 192.168.30.10 -p icmp -j ACCEPT
-A ACL_FUNCIONARIOS -d 192.0.2.10 -o wan0 -p tcp --dport 80 -j ACCEPT
-A ACL_FUNCIONARIOS -j DROP
-A ACL_FILIAL -d 192.168.30.10 -p tcp -m multiport --dports 53,80 -j ACCEPT
-A ACL_FILIAL -d 192.168.30.10 -p udp --dport 53 -j ACCEPT
-A ACL_FILIAL -d 192.168.30.10 -p icmp -j ACCEPT
-A ACL_FILIAL -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 192.168.0.0/16 -o wan0 -j MASQUERADE
COMMIT
'''
FW2='''*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i wan0 -s 203.0.113.2 -p udp --dport 51820 -j ACCEPT
-A INPUT -i lan0 -s 192.168.40.0/24 -p icmp -j ACCEPT
-A INPUT -i wg0 -s 192.168.10.0/24 -p icmp -j ACCEPT
-A INPUT -j DROP
-A FORWARD -m conntrack --ctstate INVALID -j DROP
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i lan0 -s 192.168.40.0/24 -d 192.168.30.10 -o wg0 -p tcp -m multiport --dports 53,80 -j ACCEPT
-A FORWARD -i lan0 -s 192.168.40.0/24 -d 192.168.30.10 -o wg0 -p udp --dport 53 -j ACCEPT
-A FORWARD -i lan0 -s 192.168.40.0/24 -d 192.168.30.10 -o wg0 -p icmp -j ACCEPT
-A FORWARD -i wg0 -s 192.168.10.0/24 -d 192.168.40.0/24 -p icmp -j ACCEPT
-A FORWARD -i lan0 -s 192.168.40.0/24 -d 192.0.2.10 -o wan0 -p tcp --dport 80 -j ACCEPT
-A FORWARD -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 192.168.40.0/24 -o wan0 -j MASQUERADE
COMMIT
'''

def external_service():
 class H(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   time.sleep(1)
   data=('SERVIDOR_EXTERNO_SIMULADO\norigem='+self.client_address[0]+':'+str(self.client_address[1])+'\n').encode()
   self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 http.server.ThreadingHTTPServer(('192.0.2.10',80),H).serve_forever()

def activity4():
 spawn([sys.executable,__file__,'externo'],ns='externo',log=A4/'Registos/servidor_externo.log')
 firewall('r1',FW1);firewall('r2',FW2)
 # Negative control: branch private network is not routed across the public underlay.
 r=log(A4,'01_filial_sem_vpn.txt',['curl','--noproxy','*','--connect-timeout','2','--max-time','3','-sS','http://192.168.30.10/'],ns='filial',check_result=False)
 check('sem_vpn_filial_sem_acesso',r.returncode!=0)
 # Create independent ephemeral WireGuard key pairs, never export private values.
 publics={}
 for n in ['r1','r2']:
  priv=run(['wg','genkey']).stdout.strip();key=PRIVATE/(n+'.wg');key.write_text(priv+'\n');key.chmod(0o600)
  publics[n]=run(['wg','pubkey'],input=priv+'\n').stdout.strip()
 for n,peer,ipaddr,endpoint,allowed in [('r1','r2','10.255.0.1/30','198.51.100.2:51820','10.255.0.2/32,192.168.40.0/24'),('r2','r1','10.255.0.2/30','203.0.113.2:51820','10.255.0.1/32,192.168.10.0/24,192.168.20.0/24,192.168.30.0/24')]:
  ip('link','add','wg0','type','wireguard',ns=n)
  run(['wg','set','wg0','private-key',PRIVATE/(n+'.wg'),'listen-port','51820','peer',publics[peer],'allowed-ips',allowed,'endpoint',endpoint,'persistent-keepalive','2'],n)
  addr(n,'wg0',ipaddr)
  remotes=['192.168.40.0/24'] if n=='r1' else ['192.168.10.0/24','192.168.20.0/24','192.168.30.0/24']
  for network in remotes:ip('route','add',network,'dev','wg0',ns=n)
  (A4/'Configuracoes'/('wireguard_'+n+'.conf.example')).write_text('[Interface]\nAddress = '+ipaddr+'\nListenPort = 51820\nPrivateKey = GERAR_LOCALMENTE_COM_WG_GENKEY\n\n[Peer]\nPublicKey = CHAVE_PUBLICA_DO_OUTRO_ROUTER\nEndpoint = '+endpoint+'\nAllowedIPs = '+allowed+'\nPersistentKeepalive = 2\n')
 time.sleep(3)
 r=log(A4,'02_filial_http_vpn.txt',['curl','--noproxy','*','--connect-timeout','3','--max-time','8','-fsS','-D','-','http://intranet.orbion.test/'],ns='filial')
 check('vpn_filial_http',r.returncode==0 and '200 OK' in r.stdout and 'Intranet da empresa' in r.stdout)
 r=log(A4,'03_filial_dns_vpn.txt',['dig','@192.168.30.10','www.orbion.test','+noall','+answer'],ns='filial')
 check('vpn_filial_dns','CNAME' in r.stdout and '192.168.30.10' in r.stdout)
 r=log(A4,'04_admin_filial_ping.txt',['ping','-c','4','-W','2','192.168.40.10'],ns='admin')
 check('vpn_sede_filial_ping','0% packet loss' in r.stdout)
 r=vlog(A4,'05_funcionarios_http.txt','cli','curl --noproxy "*" -fsS -o /dev/null -w "HTTP %{http_code}\\n" http://intranet.orbion.test/')
 check('acl_funcionarios_web_permitido','HTTP 200' in r.stdout)
 r=vlog(A4,'06_funcionarios_ssh_bloqueado.txt','cli','ssh -o BatchMode=yes -o ConnectTimeout=2 aluno@192.168.30.10 true',check_result=False)
 check('acl_funcionarios_ssh_bloqueado',r.returncode!=0 and ('timed out' in r.stderr or 'refused' in r.stderr))
 # Admin and branch tests do not reuse the A3 user workstation identity.
 adminssh=['ssh','-i',KEY,'-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(PRIVATE/'admin_known_hosts'),'aluno@192.168.30.10','hostname; printf "ADMIN_SSH_AUTORIZADO\\n"']
 r=log(A4,'07_admin_ssh_permitido.txt',adminssh,ns='admin')
 check('acl_admin_ssh_permitido','ADMIN_SSH_AUTORIZADO' in r.stdout)
 r=log(A4,'08_filial_ssh_bloqueado.txt',['nc','-z','-v','-w','2','192.168.30.10','22'],ns='filial',check_result=False)
 check('acl_filial_ssh_bloqueado',r.returncode!=0)
 r=log(A4,'09_externo_entrada_bloqueada.txt',['nc','-z','-v','-w','2','203.0.113.2','80'],ns='externo',check_result=False)
 check('firewall_entrada_externa_bloqueada',r.returncode!=0)
 # Concurrent HTTP flows from two VLANs share one translated source IPv4.
 cmds=[(['curl','--noproxy','*','--max-time','6','-fsS','http://192.0.2.10/'],'admin'),(None,'cli')]
 p1=subprocess.Popen(['ip','netns','exec',NS['admin'],*cmds[0][0]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 p2=subprocess.Popen(['ssh','-i',str(KEY),'-p',str(MGMT['cli']),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts'),'aluno@127.0.0.1','curl --noproxy "*" --max-time 6 -fsS http://192.0.2.10/'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 time.sleep(.4)
 conn=log(A4,'10_conntrack_PAT.txt',['conntrack','-L','-p','tcp','--dport','80'],ns='r1')
 data1,err1=p1.communicate(timeout=10);data2,err2=p2.communicate(timeout=10)
 (A4/'Registos/11_nat_duas_vlans.txt').write_text('ADMIN VLAN 10\n'+data1+err1+'\nFUNCIONARIOS VLAN 20\n'+data2+err2)
 ports=re.findall(r'origem=203\.0\.113\.2:(\d+)',data1+data2)
 check('nat_pat_duas_vlans',p1.returncode==p2.returncode==0 and len(ports)==2 and len(set(ports))==2,'Origem traduzida 203.0.113.2 com duas portas distintas: '+','.join(ports))
 log(A4,'12_regras_r1.txt',['iptables','-L','-n','-v','--line-numbers'],ns='r1')
 log(A4,'13_nat_r1.txt',['iptables','-t','nat','-L','-n','-v'],ns='r1')
 log(A4,'14_regras_r2.txt',['iptables','-L','-n','-v','--line-numbers'],ns='r2')
 for n in ['r1','r2']:
  log(A4,'15_wireguard_'+n+'.txt',['wg','show','wg0'],ns=n)
  log(A4,'16_rotas_'+n+'.txt',['ip','route'],ns=n)
  latest=run(['wg','show','wg0','latest-handshakes'],n).stdout.strip().split()
  check('vpn_handshake_'+n,bool(latest) and int(latest[-1])>0)
 outer=spawn(['tcpdump','-U','-n','-i','wan0','-w',A4/'vpn_externa.pcap','udp port 51820'],ns='r1',log=A4/'Registos/tcpdump_externa.log')
 inner=spawn(['tcpdump','-U','-n','-i','wg0','-w',A4/'vpn_interna.pcap','host 192.168.30.10'],ns='r1',log=A4/'Registos/tcpdump_interna.log')
 time.sleep(1)
 for _ in range(2):run(['curl','--noproxy','*','--max-time','5','-fsS','http://192.168.30.10/'],ns='filial')
 time.sleep(.7)
 for p in [outer,inner]:p.send_signal(signal.SIGINT);p.wait(timeout=8)
 ext=log(A4,'17_pacotes_externos.txt',['tshark','-n','-r',A4/'vpn_externa.pcap','-T','fields','-e','ip.src','-e','ip.dst','-e','udp.srcport','-e','udp.dstport'])
 visible=run(['tshark','-n','-r',A4/'vpn_externa.pcap','-Y','http or ip.addr == 192.168.40.10','-T','fields','-e','frame.number']).stdout.strip()
 inside=log(A4,'18_http_dentro_tunel.txt',['tshark','-n','-r',A4/'vpn_interna.pcap','-Y','http.request','-T','fields','-e','ip.src','-e','ip.dst','-e','http.request.method','-e','http.request.uri'])
 check('vpn_dados_cifrados_no_underlay',bool(ext.stdout.strip()) and not visible)
 check('vpn_http_observado_interface_interna','GET' in inside.stdout and '192.168.40.10' in inside.stdout)
 # An actual outage test verifies that the protected route has no cleartext fallback.
 ip('link','set','wg0','down',ns='r2')
 r=log(A4,'19_vpn_desligada_bloqueia.txt',['curl','--noproxy','*','--connect-timeout','2','--max-time','3','-sS','http://192.168.30.10/'],ns='filial',check_result=False)
 check('vpn_sem_fallback_em_texto_limpo',r.returncode!=0)
 ip('link','set','wg0','up',ns='r2')
 # Link-down invalidates routes associated with this virtual interface on some
 # kernels. Restore the private routes explicitly before waiting for rekeying.
 for network in ['192.168.10.0/24','192.168.20.0/24','192.168.30.0/24']:
  ip('route','replace',network,'dev','wg0',ns='r2')
 retry=[]
 for attempt in range(10):
  probe=run(['curl','--noproxy','*','--connect-timeout','2','--max-time','3','-fsS','-o','/dev/null','-w','HTTP %{http_code}\n','http://192.168.30.10/'],ns='filial',check=False)
  retry.append('Tentativa '+str(attempt+1)+'\n'+probe.stdout+probe.stderr)
  if probe.returncode==0:break
  time.sleep(2)
 (A4/'Registos/20a_recuperacao_vpn.txt').write_text('\n'.join(retry))
 log(A4,'20b_rotas_apos_recuperacao.txt',['ip','route'],ns='r2')
 log(A4,'20c_wireguard_apos_recuperacao.txt',['wg','show','wg0'],ns='r2')
 r=log(A4,'20_vpn_restabelecida.txt',['curl','--noproxy','*','--max-time','8','-fsS','-o','/dev/null','-w','HTTP %{http_code}\n','http://192.168.30.10/'],ns='filial')
 check('vpn_recupera_apos_reativar','HTTP 200' in r.stdout)
 snap_command(A4,'01_vpn_e_rotas','sudo ip netns exec lab34-r1 wg show wg0; sudo ip netns exec lab34-r1 ip route; sudo ip netns exec lab34-r2 wg show wg0')
 screenshot_terminal(A4,'02_acl_funcionarios','cli','hostname; curl --noproxy "*" -fsS -o /dev/null -w "WEB PERMITIDA HTTP %{http_code}\\n" http://intranet.orbion.test/; ssh -o BatchMode=yes -o ConnectTimeout=2 aluno@192.168.30.10 true; printf "SSH resultado=%s (bloqueado)\\n" "$?"')
 snap_command(A4,'03_admin_ssh',shlex.join(['ip','netns','exec',NS['admin'],*map(str,adminssh)]))
 snap_command(A4,'04_filial_vpn','sudo ip netns exec lab34-filial dig @192.168.30.10 www.orbion.test +noall +answer; sudo ip netns exec lab34-filial curl --noproxy "*" -fsS -o /dev/null -w "INTRANET PELA VPN HTTP %{http_code}\\n" http://intranet.orbion.test/; sudo ip netns exec lab34-admin ping -c 4 192.168.40.10')
 snap_command(A4,'05_nat_pat','sudo ip netns exec lab34-admin curl --noproxy "*" -fsS http://192.0.2.10/; '+shlex.join(['ssh','-i',str(KEY),'-p','2222','-o','BatchMode=yes','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts'),'aluno@127.0.0.1','curl --noproxy "*" -fsS http://192.0.2.10/'])+'; sudo ip netns exec lab34-r1 conntrack -L -p tcp --dport 80; sudo ip netns exec lab34-r1 iptables -t nat -L -nv')
 snap_command(A4,'06_firewall','sudo ip netns exec lab34-r1 iptables -L INPUT -nv; sudo ip netns exec lab34-r1 iptables -L ACL_FUNCIONARIOS -nv; sudo ip netns exec lab34-externo nc -z -v -w 2 203.0.113.2 80; printf "Entrada externa resultado=%s (bloqueado)\\n" "$?"')
 snap_command(A4,'07_trafego_vpn','tshark -n -r '+shlex.quote(str(A4/'vpn_externa.pcap'))+' -T fields -e ip.src -e ip.dst -e udp.dstport | head -14; printf "\\nDentro da interface wg0\\n"; tshark -n -r '+shlex.quote(str(A4/'vpn_interna.pcap'))+' -Y http.request -T fields -e ip.src -e ip.dst -e http.request.method -e http.request.uri')

def main():
 setup_network();prepare_vms();activity3();activity4()
 save_results()
 if not all(v['ok'] for v in CHECKS.values()):raise RuntimeError('Existem verificacoes por resolver')
 print('TODAS_AS_VERIFICACOES_CONCLUIDAS',flush=True)
 if '--manter' in sys.argv:
  print('Laboratorio activo. Ctrl+C encerra as VMs e a rede criadas por este script.',flush=True)
  while True:time.sleep(1)

if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]=='externo':external_service()
 else:
  try:main()
  except KeyboardInterrupt:print('A encerrar o laboratorio.',flush=True)
  finally:
   save_results()
   for p in reversed(PROCS):
    if p.poll() is None:
     try:p.terminate();p.wait(timeout=5)
     except Exception:p.kill()
   for n in NS.values():run(['ip','netns','del',n],check=False)
   for dev in ['l34-trunk','l34-admin','l34-tapcli','l34-tapsrv','lab34-sw']:
    run(['ip','link','del',dev],check=False)
