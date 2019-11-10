import os
import socket
import threading
import time
import struct
import random

# konstanty na odbalovanie hlaviciek
HEAD_SIZE = struct.calcsize("xhi")
START_HEAD_SIZE = struct.calcsize("iicxh")


# jednoducha funkcia na zobrazovanie presneho stavu prenasania suboru
def progress_bar(current_value, total):
    percentual = ((current_value / total) * 100)
    if percentual > 99.5:
        percentual = 100
    text = "\r{0}%".format(percentual.__round__(2))
    if percentual == 100:
        percentual = 99.8
    print(text, end="\n" if percentual == 100 else "")


#########################################################
#########################################################
# -----------------SERVER--------------------------------#


# funkcia vypise detaily o prenasanych datach
def get_details(head, fname):
    print("Number of packets: ", head[0])
    print("Packet size: ", head[1] - HEAD_SIZE)
    if len(fname) != 0:
        path = os.path.abspath(fname)
        print("Path to saved file: ", path)
        print("Size of recieved file (in bytes): ", os.path.getsize(path))
    else:
        return


# vytvori socket na server, socket pocuva na akukolvek IP
def get_server_socket():
    port = int(input("Port: "))
    sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sckt.bind(("", port))
    return sckt


# funkcia skontroluje, ci je packet vporiadku. Skontroluje jeho checksum s checksumom ktory sama vypocita
def check_if_ok_packet(packet, checksum):
    if checksum == sum(packet[4:]) % 255:
        return True
    else:
        return False


# Ak sa cislo baliku zhoduje s celkovym poctom balikov, viem, ze som poslal vsetky
def check_if_is_done(head, start_head):
    if head[1] == start_head[0]:
        return True
    else:
        return False


# hlavna funkcia na prijmanie dat. Ak je argument path prazdny retazec, viem ze prijmam iba text
def receive(sckt, head, addr, path):
    whole_msg = "".encode()
    sckt.sendto("OK".encode(), addr)
    while True:
        worker = Worker('F', sckt, addr)  # thread na spracovavanie jednotlivych balikov
        sckt.settimeout(3)  # vsetych 10 balikov z danej varky musi prist do troch sekund
        try:
            for i in range(0, 10):
                packet = sckt.recvfrom(head[1])[0]
                worker.packets.append(packet)  # pridavam prijaty packet
                curr_head = struct.unpack("xhi", packet[:HEAD_SIZE])  # odbalim hlavicku
                progress_bar(curr_head[1], head[0])
                if check_if_is_done(curr_head, head):  # skontrolujem, ci je balik posledny
                    # ak je balik posledny, posuniem threadu cislo posledneho baliku,zapnem ho a pockam kym skonci
                    sckt.settimeout(None)
                    worker.last_packet = struct.unpack("xhi", packet[:HEAD_SIZE])[1]
                    worker.start()
                    worker.join()
                    # poskladam cely balik
                    whole_msg = whole_msg + worker.data
                    # ak som prijak subor:
                    if len(path) != 0:
                        fname = "file." + path.partition(".")[::-1][0]
                        f = open(fname, "wb")
                        progress_bar(curr_head[1], head[0])
                        f.write(whole_msg)
                        f.close()
                        sckt.sendto("OK".encode(), addr)
                        print()
                        get_details(head, fname)
                        # ak som prijal text:
                    else:
                        print()
                        print(whole_msg.decode("utf-8"))
                        get_details(head, "")
                    return
        except socket.timeout:
            sckt.sendto("NOT OK".encode(), addr)
            continue
        worker.start()
        worker.join()
        whole_msg = whole_msg + worker.data
        sckt.sendto("OK".encode(), addr)
        del worker


# trieda Worker na spracovavanie jednotlivych balikov
class Worker(threading.Thread):
    last_packet = 0

    def __init__(self, fileType, sock, addr):
        threading.Thread.__init__(self)
        self.type = fileType
        self.packets = []
        self.data = "".encode()
        self.bad_packets = []
        self.recieved_packets = []
        self.first_packet = 0
        self.sock = sock
        self.addr = addr

    def run(self):

        for packet in self.packets:
            head = struct.unpack("xhi", packet[:HEAD_SIZE])
            if packet == self.packets[0]:
                self.first_packet = head[1]
            if check_if_ok_packet(packet, head[0]):
                self.recieved_packets.append((head[1], packet[HEAD_SIZE:]))
            else:
                print("\nBAD PACKET DETECTED: ", head[1])
                while True:
                    self.sock.sendto(str(head[1]).encode(), self.addr)
                    msg = self.sock.recvfrom(1500)[0]
                    head = struct.unpack("xhi", msg[:HEAD_SIZE])
                    if check_if_ok_packet(msg, head[0]):
                        self.recieved_packets.append((head[1], msg[HEAD_SIZE:]))
                        self.sock.sendto("OK".encode(), self.addr)
                        break
                    self.sock.sendto(str(head[1]).encode(), self.addr)
                    continue
        i = 0
        while len(self.recieved_packets) != 0:
            for pckt in self.recieved_packets:
                if pckt[0] == self.first_packet + i:
                    self.data = self.data + pckt[1]
                    i = i + 1
                    self.recieved_packets.remove(pckt)
                    break


# kontrola toho, ci je startovacia sprava v poriadku. kontrolujem ju rovnakym sposobom ako beznu spravu,
# ale kvoliinej strukture potrebujem dve funkcie
def check_if_ok_first_message(data, checksum):
    if checksum == sum(data[:9]) % 255:
        return True
    else:
        return False


# zacnem cast programu server. Vypis pocuvania, spracovanie startovacej spravy
def start_server(sckt):
    print("Server is listening..")
    try:
        while True:
            bytes_data = sckt.recvfrom(256)
            head = bytes_data[0][:START_HEAD_SIZE]
            head = struct.unpack("iich", head)  # odbalenie startovacej spravy
            # ako keepalive posielam startovaciu spravu ktora je cela nulova a ako typ suboru ma K
            if head[0] == 0 and head[1] == 0 and head[2].decode("utf-8") == 'K' and head[3] == 0:
                continue
            if not check_if_ok_first_message(bytes_data[0], head[3]):
                sckt.sendto("NOT".encode(), bytes_data[1])
                continue
            if head[2].decode("utf-8") == 'T':
                receive(sckt, head, bytes_data[1], "")
                sckt.sendto("OK".encode(), bytes_data[1])
                print()
                if input("Press any button to continue, Q to quit").lower() == 'q':
                    print("Shutting down...")
                    sckt.close()
                    return
                print("Server is listening..")
                continue
            if head[2].decode("utf-8") == 'F':
                print("Receiving...")
                receive(sckt, head, bytes_data[1], bytes_data[0][START_HEAD_SIZE:].decode("utf-8"))
                print("Done.")
                if input("Press any button to continue, Q to quit").lower() == 'q':
                    print("Shutting down...")
                    sckt.close()
                    return
                # ak som prijal subor, zapnem timeout na keepalive
                sckt.settimeout(40)
                print("Server is listening..")
                continue
    # ak nedostanem ziadny keepalive message potom co som spustil timer, socket zatvorim
    except socket.timeout:
        print("No traffic detected, shutting down..")
        sckt.close()


# -----------------SERVER--------------------------------#
#########################################################
#########################################################


#########################################################
#########################################################
# -----------------CLIENT--------------------------------#
# jadro client casti projektu, je tu vyber velkosti fragmentu, cesta k suboru,
# simulacia chyby atd.
def send(sock, ip, port, KLthread, dataType):
    path = ""
    message = ""
    content = "".encode()

    try:
        if dataType == 't':
            bufferSize = int(input("Enter fragment size (1 - 1466): ")) + HEAD_SIZE
            message = input("Enter message: ")
        else:
            bufferSize = int(input("Enter fragment size (100 - 1466): ")) + HEAD_SIZE
            if bufferSize - HEAD_SIZE < 100 or bufferSize - HEAD_SIZE > 1466:
                print("You entered too small value, setting fragment size to 100.")
                bufferSize = 100 + HEAD_SIZE
            path = input("Enter path: ")
        Corr = input("Send corrupt packets? Y/N: ")
        if dataType != 't':
            f = open(path, "rb")
            content = f.read()
        serverAddressPort = (ip, port)
        if dataType == 't':
            packets = make_packets(bufferSize, message.encode(), 'T')
        else:
            packets = make_packets(bufferSize, content, 'F')

        bad_packet = random.randrange(0, len(packets[1]))
        # ak pouzivatel nechce simulovat chybu, cislo packetu ktory ma byt poskodeny dam na cislo -1
        if Corr == 'n':
            bad_packet = -1
        KLthread.shutDown = True
        if dataType == 't':
            start_message = packets[0]
        else:
            # ak posielam subor, k startovacej sprave pripojim aj cestu k suboru ktory posielam
            start_message = packets[0] + path.encode()
        # tu zacnem posielat startovaciu spravu. ak pride v poriadku, hned skoncim, inak ju posielam
        # az kym nepride bez chyby
        while True:
            sock.sendto(start_message, serverAddressPort)
            resp = sock.recvfrom(256)
            if resp[0].decode("utf-8") == "OK":
                break
            else:
                continue
        print("Sending file...")
        if not bad_packet < 0:
            print("Packet number ", bad_packet, " is corrupted.")
        # tu zacinam posielat normalne baliky. Vzdy po desiatich, po kazdej varke desiatich balikov
        # cakam na ACK od serveru aby som vedel ako sa mam riadit dalej
        for i in range(0, len(packets[1]), 10):
            for j in range(i, i + 10):
                progress_bar(j, len(packets[1]))
                if not j == len(packets[1]):
                    if j == bad_packet:
                        sock.sendto(packets[1][j][:HEAD_SIZE], serverAddressPort)
                        continue
                    sock.sendto(packets[1][j], serverAddressPort)
                else:
                    break
            # cakam na ACK
            message = sock.recvfrom(256)
            # po 10 balikoch mi odozva moze prist v troch variantach:
            # OK - baliky prisli vsetky v poriadku, posielam dalej
            # NOT OK - jeden alebo viac balikov sa stratilo, musim poslat znovu danych 10 balikov
            # INE - ak mi nepride OK alebo NOT OK, pride mi cislo baliku, ktory musim poslat znovu lebo bol poskodeny
            if message[0].decode("utf-8") == "OK":
                continue
            # chybajuci balik, posielam ich po jednom a cakam na odozvu
            elif message[0].decode("utf-8") == "NOT OK":
                for j in range(i, i + 10):
                    if not j == len(packets[1]):
                        sock.sendto(packets[1][j], serverAddressPort)
                message = sock.recvfrom(256)
                if message[0].decode("utf-8") == "OK":
                    continue
            # prislo cislo, posielam dany balik az dokym nepride v poriadku
            else:
                num = int(message[0].decode("utf-8"))
                while 1:
                    sock.sendto(packets[1][num], serverAddressPort)
                    message = sock.recvfrom(256)
                    if message[0].decode("utf-8") == "OK":
                        break
                    continue
                continue
        print()
        # vypise detaily odosielanych dat
        get_details(struct.unpack("iich", packets[0]), path)
        print()
    except ValueError:
        print("You entered invalid data. Please try again.")
        return
    except socket.gaierror:
        raise Exception()


# funckia na vytvorenie jednotlivych balikov na posielanie a zaroven startovacej spravy
def make_packets(buf_size, packet_data, file_type):
    packets = []
    num_of_packets = (len(packet_data) // (buf_size - HEAD_SIZE)) + 1
    start_message = struct.pack("iicx", num_of_packets, buf_size, file_type.encode("utf-8"))
    checksum = struct.pack("h", sum(start_message) % 255)  # checksum pre startovaciu spravu
    start_message = start_message + checksum
    if file_type == 'F':
        # ak posielam subor, ukazem progress bar aj pri vytvarani balikov zo suboru pretoze to trva dlhsie
        print("Making packets...")
    for i in range(0, num_of_packets + 1):
        if file_type == 'F':
            progress_bar(i, num_of_packets + 1)
        header = struct.pack("i", i)
        message = header + packet_data[0:buf_size - HEAD_SIZE]
        checksum = struct.pack("xh", sum(message) % 255)  # checksum pre koncovu spravu
        message = checksum + message
        packets.append(message)
        packet_data = packet_data[buf_size - HEAD_SIZE:]
    print()
    return start_message, packets


# vytvori socket pre klienta
def get_client_socket():
    UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return UDPServerSocket


# thread na keepalive spravy. nachadzaju sa v nom dve premenne. Cez ne kontrolujem samotny chod threadu
class KeepAliveThread(threading.Thread):
    shutDown = False  # ak je shutdown True, KL spravy sa budu posielat
    kill = False  # ak je kill True, cely thread skonci a zanikne

    def __init__(self, sock, ip, port):
        threading.Thread.__init__(self)
        self.sock = sock
        self.serverAddressPort = (ip, port)

    def run(self):
        try:
            while True:
                time.sleep(10)  # KL posielam kazdych 10 sekund
                if self.kill:
                    return
                if not self.shutDown:
                    self.sock.sendto(struct.pack("iich", 0, 0, 'K'.encode(), 0), self.serverAddressPort)
        except:
            raise Exception()


# zapne hlavne menu pre pouzivatela na strane client. Na zaciatku vytvorim KL thread
def start_client(sckt):
    try:
        dest_ip = input("Enter destination IP: ")
        dest_port = int(input("Enter destination port: "))
        keepAlive = "OFF"
        thread1 = KeepAliveThread(sckt, dest_ip, dest_port)
        thread1.daemon = True
        thread1.shutDown = True
        thread1.start()
        while True:
            print("m = message")
            print("f = file")
            print("q = disconnect")
            print("k = turn on/off keepAlive(currently " + keepAlive + ")")
            inp = input()
            if inp == "m":
                send(sckt, dest_ip, dest_port, thread1, 't')
                thread1.shutDown = False
                continue
            if inp == "f":
                send(sckt, dest_ip, dest_port, thread1, 'f')
                # po odoslani suboru sa vzdy zapne KL thread
                keepAlive = "ON"
                thread1.shutDown = False
                continue
            # KL thread mozeme vypinak a zapinat jednoduchym toggle switchom
            if inp == "k":
                if keepAlive == "ON":
                    thread1.shutDown = True
                    keepAlive = "OFF"
                else:
                    thread1.shutDown = False
                    keepAlive = "ON"
            if inp == "q":
                sckt.close()
                thread1.kill = True
                print("Shutting down client...")
                thread1.join()
                print("Done.")
                return
        sckt.close()
    # ak pouzivatel zada zle vstupy, jednoducho zachytim akykulvek exeption a restartujem funkciu
    except Exception:
        print("Server is probably offline, or you entered invalid data, please try again later.")
        return


# -----------------CLIENT--------------------------------#
#########################################################
#########################################################

# zaciatok programu, moznosti na zapnutie klienta alebo serveru
def start_program():
    while True:
        print("s = start server")
        print("c = start client")
        ui = input()
        if ui == "c":
            sckt = get_client_socket()
            start_client(sckt)
        if ui == "s":
            try:
                sckt = get_server_socket()
                start_server(sckt)
            except:
                print("Error occurred, please try again.")
                continue


start_program()
