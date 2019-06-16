import socket
import os
from subprocess import Popen
from subprocess import check_output
from xml.etree.ElementTree import fromstring
from ipaddress import IPv4Interface, IPv6Interface
import zeep
from pythonping import ping
import ctypes, sys


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if is_admin():
    def getNics():
        cmd = 'wmic.exe nicconfig where "IPEnabled  = True" get ipaddress,MACAddress,IPSubnet,DNSHostName,Caption,DefaultIPGateway /format:rawxml'
        xml_text = check_output(cmd, creationflags=8)
        xml_root = fromstring(xml_text)

        nics = []
        keyslookup = {
            'DNSHostName': 'hostname',
            'IPAddress': 'ip',
            'IPSubnet': '_mask',
            'Caption': 'hardware',
            'MACAddress': 'mac',
            'DefaultIPGateway': 'gateway',
        }

        for nic in xml_root.findall("./RESULTS/CIM/INSTANCE"):
            # parse and store nic info
            n = {
                'hostname': '',
                'ip': [],
                '_mask': [],
                'hardware': '',
                'mac': '',
                'gateway': [],
            }
            for prop in nic:
                name = keyslookup[prop.attrib['NAME']]
                if prop.tag == 'PROPERTY':
                    if len(prop):
                        for v in prop:
                            n[name] = v.text
                elif prop.tag == 'PROPERTY.ARRAY':
                    for v in prop.findall("./VALUE.ARRAY/VALUE"):
                        n[name].append(v.text)
            nics.append(n)

            # creates python ipaddress objects from ips and masks
            for i in range(len(n['ip'])):
                arg = '%s/%s' % (n['ip'][i], n['_mask'][i])
                if ':' in n['ip'][i]:
                    n['ip'][i] = IPv6Interface(arg)
                else:
                    n['ip'][i] = IPv4Interface(arg)
            del n['_mask']

        return nics


    while True:

        os.system(
            '''netsh interface ipv4 set address name="Ethernet" static 192.168.0.2 255.255.255.0''')  # Задаём интерфейсу Ethernet статический IP

        pkt = None
        nics = getNics()
        ip = []

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        for i in nics:  # C помощью данных строк, мы исключаем из рассмотрения интерфейсы данного ПК
            ip.append(str(i['ip'][0])[:-3])

        print("Включите устройство")

        while True:
            try:
                s.bind(("192.168.0.2", 0))
            except OSError:
                pass
            else:
                break
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print("Идёт поиск...")

        p = Popen('tftpd64.exe')
        while True:
            pkt = s.recvfrom(65565)
            if pkt[1][0] not in ip and pkt[1][0] != "0.0.0.0" and pkt[1][0] != "127.0.0.1" and pkt[1][
                0] != "192.168.0.2":

                nics = getNics()  # C помощью данных строк, мы исключаем из рассмотрения интерфейсы данного ПК
                for i in nics:
                    if i not in ip:
                        ip.append(str(i['ip'][0])[:-3])

                if pkt[1][0] not in ip and pkt[1][0].startswith("192.168.0.1"):
                    vkl = False
                    print("Динамический IP-адрес устройства: ", pkt[1][0])
                    os.system('''start iexplore "{0}"'''.format(pkt[1][0]))
                    break
                elif pkt[1][0] not in ip:
                    ip_new = pkt[1][0]
                    n = ip_new.rfind('.') + 1
                    ip_last = int(ip_new[n:]) + 1
                    ip_new = ip_new[:n] + str(ip_last)
                    os.system(
                        '''netsh interface ipv4 set address name="Ethernet" static {0} 255.255.255.0'''.format(ip_new))
                    responce = ping("{0}".format(pkt[1][0]))
                    if responce._responses[0].success or responce._responses[1].success or responce._responses[
                        2].success or \
                            responce._responses[3].success:
                        print("IP-адрес устройства: ", pkt[1][0])
                        os.system('''start iexplore "{0}"'''.format(pkt[1][0]))
                        break
                    else:
                        os.system(
                            '''netsh interface ipv4 set address name="Ethernet" static 192.168.0.2 255.255.255.0''')

        p.kill()
        n = input('''Если хотите просканировать новое устройство
                отсоедините текущее устройство, подсоедините
                выключенное новое устройство и нажмите любую клавишу:''')
        if n == 'q' or 'Q' or 'й' or 'Й':
            os.system(
                '''netsh interface ip set address "Ethernet" dhcp''')
            raise SystemExit(1)
else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, "", 1)
