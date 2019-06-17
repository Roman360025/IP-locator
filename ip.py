import ctypes, sys


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if is_admin():
    import socket
    import os
    from subprocess import Popen
    from subprocess import check_output
    import xml.etree.ElementTree
    from ipaddress import IPv4Interface, IPv6Interface
    import shutil
    from time import sleep


    def getNics():
        cmd = 'wmic.exe nicconfig where "IPEnabled  = True" get ipaddress,MACAddress,IPSubnet,DNSHostName,Caption,DefaultIPGateway /format:rawxml'
        xml_text = check_output(cmd, creationflags=8)
        xml_root = xml.etree.ElementTree.fromstring(xml_text)

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
        shutil.copyfile(os.path.abspath(r"settings\tftpd32.ini"), "tftpd32.ini")
        os.system(
            '''netsh interface ipv4 set address name="Ethernet" static 192.168.0.2 255.255.255.0''')  # Задаём интерфейсу Ethernet статический IP

        pkt = None
        statbuf = os.stat("tftpd32.ini")

        try:
            nics = getNics()
        except xml.etree.ElementTree.ParseError:
            nics = []

        ip = []

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        if nics != []:
            for i in nics:  # C помощью данных строк, мы исключаем из рассмотрения интерфейсы данного ПК
                if 'ip' in i and i['ip'] != []:
                    ip.append(str(i['ip'][0])[:-3])
                if 'gateway' in i and i['gateway'] != []:
                    ip.append(str(i['gateway'][0]))

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

        found = False
        line_old = ""

        p = Popen("tftpd64.exe")
        while True:
            pkt = s.recvfrom(65565)
            if pkt[1][0] not in ip and pkt[1][0] != "0.0.0.0" and pkt[1][0] != "127.0.0.1" and pkt[1][
                0] != "192.168.0.2":

                if pkt[1][0].startswith("192.168.0.1"):
                    nics = getNics()  # C помощью данных строк, мы исключаем из рассмотрения интерфейсы данного ПК
                    for i in nics:
                        if str(i['ip'][0])[:-3] not in ip:
                            ip.append(str(i['ip'][0])[:-3])

                if pkt[1][0] not in ip and pkt[1][0].startswith("192.168.0.1"):
                    print("Динамический IP-адрес устройства: ", pkt[1][0])
                    os.system('''start iexplore "{0}"'''.format(pkt[1][0]))
                    break
                elif pkt[1][0] not in ip:
                    ip_new = pkt[1][0]
                    n = ip_new.rfind('.') + 1
                    ip_new = ip_new[:n] + str(253)
                    while ip_new in ip and ip_new == pkt[1][0]:
                        ip_last = int(ip_new[n:]) - 1
                        ip_new = ip_new[:n] + str(ip_last)
                    os.system(
                        '''netsh interface ipv4 set address name="Ethernet" static {0} 255.255.255.0'''.format(ip_new))
                    response = os.system("ping {0} > nul".format(pkt[1][0]))
                    if response == 0:
                        print("IP-адрес устройства: ", pkt[1][0])
                        os.system('''start iexplore "{0}"'''.format(pkt[1][0]))
                        break
                    else:
                        ip.append(ip_new)
                        ip.append(pkt[1][0])
                        os.system(
                            '''netsh interface ipv4 set address name="Ethernet" static 192.168.0.2 255.255.255.0''')

            if os.stat("tftpd32.ini") != statbuf:
                f = open("tftpd32.ini")
                for line in f:
                    if line[8:10] == "IP" and "46:46:3A:46:46:3A" not in line_old:
                        nics = getNics()  # C помощью данных строк, мы исключаем из рассмотрения интерфейсы данного ПК
                        for i in nics:
                            if str(i['ip'][0])[:-3] not in ip:
                                ip.append(str(i['ip'][0])[:-3])
                        if line[11:-1] not in ip:
                            response = os.system("ping {0} > nul".format(line[11:-1]))
                            if response == 0:
                                f.close()
                                print("Динамический IP-адрес устройства: ", line[11:-1])
                                sleep(10)
                                os.system('''start iexplore "{0}"'''.format(line[11:-1]))
                                found = True
                                break
                            else:
                                ip.append(line[11:-1])
                    line_old = line
                    statbuf = os.stat("tftpd32.ini")
                f.close()

            if found:
                break

        p.kill()

        n = input('''Если хотите просканировать новое устройство:
                    1. Отсоедините текущее устройство 
                    2. Подсоедините выключенное новое устройство
                    3. Нажмите "Enter":''')
        if n == 'q' or n == 'Q' or n == 'й' or n == 'Й':
            os.system(
                '''netsh interface ip set address "Ethernet" dhcp''')
            raise SystemExit(1)

else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, "", 1)
