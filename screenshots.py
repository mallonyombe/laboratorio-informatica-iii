"""Screenshots of real Wireshark and xterm windows on the ephemeral VM."""
import json,os,subprocess,time,signal
from pathlib import Path
HERE=Path(__file__).resolve().parent
OUT=HERE/'evidencias'
SHOTS=OUT/'capturas';SHOTS.mkdir(exist_ok=True)
analysis=json.loads((OUT/'analise.json').read_text())
os.environ['DISPLAY']=':99'
os.environ['QT_ACCESSIBILITY']='0'
xvfb=subprocess.Popen(['Xvfb',':99','-screen','0','1600x1000x24','-nolisten','tcp'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(1)
wm=subprocess.Popen(['openbox'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(.6)
def capture(name,argv,delay=2.5):
    with (OUT/'registos'/('gui_'+name+'.log')).open('w') as log:
        p=subprocess.Popen(argv,stdout=log,stderr=log)
        try:
            time.sleep(delay)
            if p.poll() is not None:raise RuntimeError(name+' exited '+str(p.returncode))
            subprocess.run(['import','-display',':99','-window','root',str(SHOTS/(name+'.png'))],check=True)
        finally:
            p.terminate()
            try:p.wait(timeout=4)
            except subprocess.TimeoutExpired:p.kill()
    time.sleep(.3)
try:
    common=['wireshark','--fullscreen','-n','-r',str(OUT/'atividade1.pcap')]
    capture('01_wireshark_geral',common)
    capture('02_handshake_tcp',common+['-Y','tcp.stream == '+analysis['http_stream'],'-g',analysis['handshake'][0]['frame.number']])
    capture('03_http',common+['-Y','http','-g',analysis['sample_http_frame']])
    capture('04_telnet',common+['-Y','telnet','-g',analysis['sample_telnet_frame']])
    capture('05_https_tls',common+['-Y','tls'])
    capture('06_ssh',common+['-Y','ssh'])
    for name,files in [('07_cli_diagnostico',['01_ping.txt','02_traceroute.txt','03_arp.txt','04_nslookup.txt']),('08_http_telnet_stream',['http_follow_stream.txt','telnet_follow_stream.txt']),('09_netstat_ssh',['08_netstat.txt'])]:
        text='\n'.join((OUT/'registos'/f).read_text() for f in files)
        txt=OUT/'registos'/(name+'_captura.txt');txt.write_text(text)
        capture(name,['xterm','-fa','DejaVu Sans Mono','-fs','13','-geometry','150x43+0+0','-title','Laboratorio III - resultados reais','-e','bash','-c','cat "$1"; sleep 60','xterm',str(txt)],1)
finally:
    wm.terminate();xvfb.terminate()
