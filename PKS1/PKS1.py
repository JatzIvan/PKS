import socket
import struct
import io
import math
import os
import time
import sys, msvcrt

ADDR_Servera, PORT, addr, VOLBA = None, None, None, None
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.setblocking(True)

# Funkciu som skopiroval zo stackoverflow, ale upravil som si ju podľa svojej potreby, pri necinnosti sa kazdych 30 sek posle fragment keep alive
def readInput( caption, default, timeout=30):
    zaciatocny_cas = time.time()
    sys.stdout.write('%s'%(caption))
    vstup = ''
    while True:
        if msvcrt.kbhit():
            byte_arr = msvcrt.getche()
            if ord(byte_arr) == 13:
                break
            elif ord(byte_arr) >= 32:                                  
                vstup += "".join(map(chr,byte_arr))
        if len(vstup) == 0 and (time.time() - zaciatocny_cas) > timeout:
            break
    if len(vstup) > 0:
        return vstup
    else:
        return default
    
# crc som ziskal z internetu
def crc16(data, poly=0x8408):
    data = bytearray(data)
    crc = 0xFFFF                                                                
    for byte in data:
        cur_byte = 0xFF & byte
        for _ in range(0, 8):
            if (crc & 0x0001) ^ (cur_byte & 0x0001):
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            cur_byte >>= 1
    crc = (~crc & 0xFFFF)
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    return crc & 0xFFFF                                                         #

#funkcia simuluje odosielatela. Odosielatel dokaze urcovat velkost odosielaneho fragmentu, moze simulovat chybny fragment, posielat subor alebo spravu
def Odosielatel():
    chybnyBool1, CelkovaDL, suborT, crc, chybneFrag, TypSpravy, pocFragmentov = None, None, None, None, None, None, None
    chunks = []
    while True:
        TypSuboru = int(input("Ak chcete poslat subor zadajte 1\nAk chcete poslat spravu zadajte 2\n"))
        if ((TypSuboru == 1) or (TypSuboru == 2)):
            break
    if (TypSuboru == 2):
        while True:
            chybneFrag = input("Mam zaslat chybne fragmenty? (y/n):")
            if ((chybneFrag == 'y') or (chybneFrag == 'n')):
                break
            else:
                print("Zvolili ste nespravnu moznost")
        while True:
            Fragment = int(input("Zadajte velkost fragmentu, hranice su (13,1500>: "))
            if ((Fragment <= 13) or (Fragment > 1500)):
                print("Zadali ste nespravnu velkost fragmentu. Hranice su (13,1500>")
            else:
                break
        Sprava = input("Zadajte spravu: ")
        TypSpravy = '6'
        suborT = False
        if (Fragment > 1455):                                                                                           
            Fragment -= 32
        pocFragmentov = math.ceil(len(Sprava.encode()) / (Fragment - 13))                                           
    if (TypSuboru == 1):
        while True:
            chybneFrag = input("Mam zaslat chybne fragmenty? (y/n):")
            if ((chybneFrag == 'y') or (chybneFrag == 'n')):
                break
            else:
                print("Zvolili ste nespravnu moznost")
        while True:
            Fragment = int(input("Zadajte velkost fragmentu, hranice su (13,1500>: "))
            if ((Fragment <= 13) or (Fragment > 1500)):
                print("Zadali ste nespravnu velkost fragmentu. Hranice su (13,1500>")
            else:
                break
        while True:
            Sprava = input("Zadajte directory: ")
            try:
                io.open(Sprava)
            except:
                print("Zadali ste neplatnu cestu k suboru, alebo dany subor neexistuje")
            else:
                break
        TypSpravy = '7'
        suborT = True
        if (Fragment > 1455):                                                                                           
            Fragment -= 32
        pocFragmentov = math.ceil(os.path.getsize(Sprava) / (Fragment - 13))  # velkost Headeru 13                      
    if (chybneFrag == 'y'):
        chybnyBool1 = True
    elif (chybneFrag == 'n'):
        chybnyBool1 = False
    print("Pocet fragmentov: ", pocFragmentov)                
    pomocnyPoc = pocFragmentov
    HEAD = struct.pack(">ciii", TypSpravy[0].encode('ascii'), Fragment, len(Sprava.encode()), 0)
    socket.sendto(HEAD, addr)
    CelkovaDL = pocFragmentov
    if (suborT == True):                                                                                                
        File = io.open(Sprava, 'rb')
        NazovFile = os.path.basename(Sprava)                                                              
        pocetFragmentov = math.ceil(len(NazovFile) / (Fragment - 13))                                                  
        FILE = io.BytesIO(NazovFile.encode())
        for i in range(pocetFragmentov):
            if (i == pocetFragmentov - 1):
                poslednyF = '8'
                HEAD = struct.pack(">ciii", poslednyF[0].encode('ascii'), 0, 0, 0) + FILE.read(Fragment - 13)
            else:
                HEAD = struct.pack(">ciii", TypSpravy[0].encode('ascii'), 0, 0, 0) + FILE.read(Fragment - 13)
            socket.sendto(HEAD, addr)
    if (suborT == False):
        File = io.BytesIO(Sprava.encode())
    print("Velkost a pocet fragmentov je:", Fragment, "/", pocFragmentov)                                              
    if (CelkovaDL >= 10):
        for i in range(0, 10):
            chunks.append(File.read(Fragment - 13))
        CelkovaDL -= 10
    else:                                                                                                              
        for i in range(0, CelkovaDL):
            chunks.append(File.read(Fragment - 13))
        CelkovaDL = 0
    increment = 0
    while True:                                                                             
        if (pomocnyPoc >= 10):
            posli_pocetF = 10
        else:
            posli_pocetF = pomocnyPoc
        if (increment == (pocFragmentov - 1)):                                                                         
            stav = '8'
        else:                                                                           
            stav = TypSpravy
        if (increment <= (pocFragmentov - 1)):
            Byt = chunks[increment % 10]                                                                                
            crc = crc16(Byt)                                                                                          
            if ((chybnyBool1 == True) and (increment == 0)):                                                           
                HEAD = struct.pack(">ciii", stav[0].encode('ascii'), increment % 10, posli_pocetF, crc + 1) + Byt
                chybnyBool1 = False
            else:
                HEAD = struct.pack(">ciii", stav[0].encode('ascii'), increment % 10, posli_pocetF, crc) + Byt

            socket.sendto(HEAD, addr)
            print(increment, pocFragmentov)
        if (((increment + 1) % 10 == 0) or ((increment + 1) == pocFragmentov)):                                        
            while True:
                socket.settimeout(10)
                try:                                                                                                    
                    DATA = socket.recvfrom(13)[0]
                except:
                    if (KeepAlive(True) == 1):
                        return
                else:
                    Chybn, Poradie_chyb, pocet_chyb, chyba = struct.unpack(">ciii", DATA)
                if (chr(Chybn[0]) == '1'):                                                                            
                    Keep = '1'
                    HEAD = struct.pack(">ciii", Keep[0].encode('ascii'), 0, 0, 0)
                    socket.sendto(HEAD, addr)
                    DATA = socket.recvfrom(13)[0]
                    Chybn, Poradie_chyb, pocet_chyb, chyba = struct.unpack(">ciii", DATA)
                if (chr(Chybn[0]) == '4'):                                                                              
                    print("Fragmenty dorazili\n")
                    if ((increment + 1) == pocFragmentov):
                        break
                    chunks.clear()
                    pomocnyPoc = CelkovaDL
                    if (CelkovaDL > 10):                                                                                
                        for i in range(0, 10):
                            chunks.append(File.read(Fragment - 13))
                        CelkovaDL -= 10
                        break
                    else:
                        for i in range(0, CelkovaDL):
                            chunks.append(File.read(Fragment - 13))
                        CelkovaDL = 0
                        break
                if (chr(Chybn[0]) == '5'):                                                                              
                    print("Nespravne dorazilo", pocet_chyb, "fragmentov\n")
                    Poradie_chyb = int(Poradie_chyb)
                    Poradie_chyb += math.pow(2, 11)                                                                     
                    BinarnaS = "{0:b}".format(int(Poradie_chyb))                                                        
                    for i in range(10):
                        if (BinarnaS[11 - i] == '1'):                                                                   
                            Byt = chunks[i]
                            stav = '9'
                            crc = crc16(Byt)
                            HEAD = struct.pack(">ciii", stav[0].encode('ascii'), i, posli_pocetF, crc) + Byt
                            socket.sendto(HEAD, addr)
                    #if (increment == (pocFragmentov - 1)):
                        #break
            if((increment == (pocFragmentov-1))and(chr(Chybn[0])=='4')):                                                
                stav = '8'
                HEAD = struct.pack(">ciii", stav[0].encode('ascii'), 0, posli_pocetF, -1)
                socket.sendto(HEAD, addr)
                break
        increment += 1
    File.close()


def Prijemca():                                                                                                         
    Doraz = input("Chcete vypisovat na konzolu stav dorazenych fragmentov? (y/n)")
    print("Cakam na spojenie...")
    chyba, info, Pstring, VelkostFragmentu, Chybne, suborT, Direct, crc, testPocet = None, None, None, None, 0, None, None, None, 0
    Dobre, Chybne, poc, keepAlive, testPocitadlo = [], 0, 0, '1', 0
    while True:                                                                                                         
        socket.settimeout(None)
        info = socket.recvfrom(13)[0]
        HOP, VelkostFragmentu, DIR, chyba = struct.unpack(">ciii", info)
        if ((chr(HOP[0]) == '6') or (chr(HOP[0]) == '7')):
            break

    if (chr(HOP[0]) == '7'):                                                                                            
        print("Prijimam subor")
        #print(DIR)
        NazovSuboru = io.BytesIO("".encode())
        while True:                                                                                                     
            DirData = socket.recvfrom(13 + VelkostFragmentu)[0]
            Prepinac = DirData[:13]
            Direct = DirData[13:]
            NazovSuboru.write(Direct)
            x, chyba, chyba, chyba = struct.unpack(">ciii", Prepinac)
            if (chr(x[0]) == '8'):
                break
        print("Directory je:prijate\\",NazovSuboru.getvalue().decode())                                                
        if(os.path.exists("stiahnute")):
            pass
        else:
            os.mkdir("stiahnute")                                                                                       
        File = io.open("stiahnute\\"+NazovSuboru.getvalue().decode(), 'wb')
        suborT = True
    if (chr(HOP[0]) == '6'):                                                                                  
        print("Prijimam spravu")
        suborT = False
        File = io.BytesIO("".encode())
    print("Velkost fragmentu je:", VelkostFragmentu)
    for i in range(10):
        Dobre.append("")
    while True:
        socket.settimeout(2)
        try:
            recv_data = socket.recvfrom(VelkostFragmentu)[0]
        except:
            if (KeepAlive(True) == 1):
                break
            stav = '8'
            stav = stav.encode('ascii')
            s = 1
            poc = 1
            increment = 9
        else:
            HEAD = recv_data[:13]
            Pstring = recv_data[13:]
            if(len(Pstring)==0):
                stav='8'
                stav=stav.encode('ascii')
                s=-1
                poc=1
                increment=9
            else:
                stav, increment, pocFragmentu, s = struct.unpack(">ciii", HEAD)
                if(Doraz=='y'):
                    print(increment)
                crc = crc16(Pstring)
        if (s != -1):
            if (chr(stav[0]) == '9'):
                if (crc == s):                
                    poc -= 1
                    Chybne -= math.pow(2, increment)
                    if (Doraz == 'y'):
                        print("Dorazil dobry opravny fragment\n")
                    Dobre[increment % 10] = Pstring
                    testPocet += 1
                else:
                    if (s != crc):
                        if (Doraz == 'y'):
                            print("Dorazil chybny opravny fragment\n")
                        poc += 1
                        chyba=True
            else:
                if (crc == s):
                    if (Doraz == 'y'):
                        print("Dorazil dobry fragment\n")
                    Dobre[increment % 10] = Pstring
                    testPocet += 1
                else:
                    if (crc != s):
                        if (Doraz == 'y'):
                            print("Dorazil chybny fragment\n")
                        chyba=True
                        poc += 1
        if ((((increment + 1) % 10 == 0) or (chr(stav[0]) == '8') or ((poc == 0) and (chr(stav[0]) == '9'))) and (s != -1)): 
            if ((poc == 0) and (testPocet == pocFragmentu)):         
                testPocet = 0
                xx = '4'
                HEAD = struct.pack(">ciii", xx[0].encode('ascii'), 0, 0, 0)
                socket.sendto(HEAD, addr)
                for i in range(pocFragmentu):
                    File.write(Dobre[i])
                Dobre.clear()
                for i in range(10):
                    Dobre.append("")
                chyba = False
            else:
                xx = '5'
                poc = 0
                Chybne=0
                for i in range(pocFragmentu):
                    if (Dobre[i] == ""):
                        poc += 1
                        Chybne += math.pow(2, i)
                if(poc>0):
                    HEAD = struct.pack(">ciii", xx[0].encode('ascii'), int(Chybne), poc, 0)
                    socket.sendto(HEAD, addr)
                    chyba = True
                else:
                    xx='4'
                    HEAD = struct.pack(">ciii", xx[0].encode('ascii'), 0,0,0)
                    socket.sendto(HEAD, addr)
                    for i in range(pocFragmentu):
                        File.write(Dobre[i])
                    Dobre.clear()
                    for i in range(10):
                        Dobre.append("")
                    chyba = False
                    
        if ((chr(stav[0]) == '8') and (chyba == False)):       
            if (suborT == False):
                print("Sprava bola Uspesne Prijata\n", addr, ":", File.getvalue().decode())
            if (suborT == True):
                print("Subor", NazovSuboru.getvalue().decode(), "bol uspesne prijaty")
            break
    File.close()


def KeepAlive(pomoc):
    Keep = '1'
    HEAD = struct.pack(">ciii", Keep[0].encode('ascii'), 0, 0, 0)
    socket.sendto(HEAD, addr)
    socket.settimeout(20)
    try:
        recv = socket.recvfrom(13)[0]
    except:
        print("Spojenie bolo stratene")
        return 1
    else:
        print("Spojenie je stale aktivne")
        if(pomoc==True):
            return 2
    print("umrel som")

def KlientKeep():
    socket.settimeout(20)
    try:
        recv = socket.recvfrom(13)[0]
    except:
        print("Spojenie bolo stratene")
        return 1
    else:
        Keep = '1'
        HEAD = struct.pack(">ciii", Keep[0].encode('ascii'), 0, 0, 0)
        socket.sendto(HEAD, addr)
        print("Spojenie je stale aktivne")
        return 2

def Volba(TypUzivatel):
    while True:
        TypUzivatela = readInput("Zadajte:\n 1 pre odosielatela\n 2 pre prijemcu\n 3 pre ukoncenie programu\n","999")
        if(TypUzivatela=="999"):                                    
            if(TypUzivatel==True):
                KeepAlive(True)
            if(TypUzivatel==False):
                KlientKeep()
        if (int(TypUzivatela) == 1):                
            Odosielatel()
        if (int(TypUzivatela) == 2):        
            Prijemca()
        if (int(TypUzivatela) == 3):        
            if (TypUzivatel == True):
                socket.close()
            break


if (VOLBA == None):
    while True:
        VOLBA = int(input("Zvol:\n 1 pre server\n 2 pre klienta\n 3 pre ukoncenie programu\n\n"))
        if ((VOLBA == 1) or (VOLBA == 2) or (VOLBA == 3)):
            break
if (VOLBA == 1):
    while True:
        ADDR_Servera = input("Zadaj Adresu tohto servera:\n")
        PORT = int(input("Zadaj Port pre tento server:\n"))
        try:
            socket.bind((ADDR_Servera, PORT))                   
        except:
            print("Zadali ste neplatnu IP alebo PORT")
        else:
            print("Socket bol vytvoreny pre adresu:", ADDR_Servera, ":", PORT)
            break
    print("Cakam na klienta\n")
    DATA, addr = socket.recvfrom(13)
    x = '2'
    HEAD = struct.pack(">ciii", x[0].encode('ascii'), 0, 0, 0)
    socket.sendto(HEAD, addr)
    print("Spojenie s", addr[0], ":", addr[1], "bolo nastolene\n")
    VOLBA = None
    TypUzivatel = True
    Volba(TypUzivatel)
if (VOLBA == 2):
    adresa = input("Zadajte adresu servera:\n")
    port = int(input("Zadajte port servera:\n"))
    x = '2'
    HEAD = struct.pack(">ciii", x[0].encode('ascii'), 0, 0, 0)
    socket.sendto(HEAD, (adresa, port))
    socket.settimeout(2)
    try:
        DATA, addr = socket.recvfrom(13)
    except:
        print("Pripojenie nebolo nastolene")
    else:
        print("Spojenie so serverom", addr[0], ":", addr[1], "bola nastolena\n")
        VOLBA = None
        TypUzivatel = False
        Volba(TypUzivatel)
