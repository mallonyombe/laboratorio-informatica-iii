# Laboratório de Informática III — Actividade 1

Laboratório académico executado numa VM Ubuntu, com três namespaces de rede: cliente, router e servidor. A captura recolhe tráfego Ethernet real numa interface virtual do cliente.

## Execução de referência

- Data: 12 de Novembro de 2026.
- [Execução concluída com sucesso](https://github.com/mallonyombe/laboratorio-informatica-iii/actions/runs/43211305496).
- 148 quadros no PCAP e 9 capturas técnicas de ecrã.
- 12 verificações de análise aprovadas.
- Comandos: ping, traceroute, arp, nslookup e netstat.
- Protocolos: ARP, ICMP, DNS, TCP, HTTP, TLS, Telnet didáctico e SSH.

Os números de sequência TCP, as portas efémeras e o total de pacotes podem mudar numa repetição. As credenciais usadas são fictícias. As chaves privadas descartáveis são excluídas antes da publicação das provas.

## Ficheiros

`run_lab.py` monta a rede isolada, executa os serviços e comandos, grava o PCAP e analisa os campos com TShark.

`screenshots.py` abre o PCAP no Wireshark e mostra as transcrições num terminal real, num ecrã virtual Xvfb, guardando as capturas de ecrã.

`.github/workflows/atividade1.yml` instala os pacotes oficiais Ubuntu, executa o laboratório e guarda as provas como artefacto da execução durante 7 dias.

## Repetir

Em **Actions → Actividade 1 - captura e analise reais → Run workflow**. A execução usa um executor padrão Ubuntu. Toda a comunicação de laboratório fica nas redes isoladas 10.77.10.0/24 e 10.77.20.0/24.

Este repositório cobre a actividade 1. VLANs, OSPF, DHCP, NAT e VPN pertencem às actividades seguintes.
