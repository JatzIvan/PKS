import dpkt


while True:
    try:
        Subor=input("Zadajte nazov suboru s koncovkou .pcap\n")
        f = open(Subor, 'rb')
    except:
        print("Zadali ste nespravny nazov suboru\n")
    else:
        break
File=open('informacie.txt','r')
Vystup=open('vystup.txt','w')
Protokol,pocitadlo,ProtNaneskor,ETH,IPV_4_Info,IPV_4_Miesto,AKTip1,AKTip2,VsetkyRamce,=[],1,None,0,[],[],None,None,[]
Protokol=File.readlines()
ETHERTYPE, LSAP, IP_Protocol, TCP, UDP, ICMP = {}, {}, {}, {}, {}, {}
prepinac=-1
print("Analyzujem....")
for i in Protokol:
    Parse=i.split(" ")
    if (i[0] == "#"):
        prepinac += 1
    if(prepinac==0):
        ETHERTYPE[Parse[0][2:]]=Parse[-1]
    elif(prepinac==1):
        LSAP[Parse[0][2:]]=Parse[-1]
    elif(prepinac==2):
        IP_Protocol[Parse[0][2:]]=Parse[-1]
    elif(prepinac==3):
        TCP[Parse[0][2:]]=Parse[-1]
    elif(prepinac==4):
        UDP[Parse[0][2:]]=Parse[-1]
    elif(prepinac==5):
        ICMP[Parse[0]]=Parse[-1]

packets = dpkt.pcap.Reader(f)
pack = packets.readpkts()
pocTypov,pomoc,EtherT=-1,0,[]
EtherType=None

def vypisCele(Ramec,switch):
    #ARP - Request, IP adresa: 147.175.98.238, MACc adresa:  ???
    #Zdrojová IP: 147.175.98.231, Cieľová IP: 147.175.98.238
    for i in Ramec:
        if switch == True:
            #print(i)
            print(i[11]+", "+"IP adresa: ",str(int(i[12][:2],16))+"."+str(int(i[12][2:4],16))+"."+str(int(i[12][4:6],16))+"."+str(int(i[12][6:],16)),"MAC adresa: ",i[16])
            print("Zdrojova IP: ",str(int(i[13][:2],16))+"."+str(int(i[13][2:4],16))+"."+str(int(i[13][4:6],16))+"."+str(int(i[13][6:],16)), "Cielova IP: ",str(int(i[15][:2],16))+"."+str(int(i[15][2:4],16))+"."+str(int(i[15][4:6],16))+"."+str(int(i[15][6:],16)))
        print("rámec:",i[0])
        print("dĺžka rámca poskytnutá pcap API –",i[1],"B")
        print("dĺžka rámca prenášaného po médiu –",i[2],"B")
        print(i[3].replace("\n",""))
        print("Zdrojová MAC adresa:",end=" ")
        for j in range(1,len(i[4])+1):
            print(i[4][j - 1],end="")
            if (j % 2 == 0):
                print(" ",end="")
        print("")
        print("Cieľová MAC adresa:",end=" ")
        for j in range(1, len(i[5]) + 1):
            print(i[5][j - 1], end="")
            if (j % 2 == 0):
                print(" ", end="")
        print("")
        if(i[6]!=" "):
            print(i[6],end="")
        if (i[7] != " "):
            print("zdrojová IP adresa: ", i[7])
        if (i[8] != " "):
            print("cieľová IP adresa: ", i[8])
        if(i[9]!=" "):
            print(i[9].replace("-","").replace("_"," "),end="")
        for j in range(1, len(i[10]) + 1):
            print(i[10][j-1],end="")
            if (j % 2 == 0):
                print("",end=" ")
            if (j % 16 == 0):
                print("",end=" ")
            if (j % 32 == 0):
                print("")
        print("\n")
def vypisRamce(Ramec):
    Vypis=[]
    if(len(Ramec)<=20):
        for i in Ramec:
            Vypis.append(i)
    else:
        for i in range(0,10):
            Vypis.append(Ramec[i])
        for i in range(0,10):
            Vypis.append(Ramec[(-10)+i])
    for i in Vypis:
        print("rámec:", i[0])
        print("dĺžka rámca poskytnutá pcap API –", i[1], "B")
        print("dĺžka rámca prenášaného po médiu –", i[2], "B")
        print(i[3].replace("\n", ""))
        print("Zdrojová MAC adresa:", end=" ")
        for j in range(1, len(i[4]) + 1):
            print(i[4][j - 1], end="")
            if (j % 2 == 0):
                print(" ", end="")
        print("")
        print("Cieľová MAC adresa:", end=" ")
        for j in range(1, len(i[5]) + 1):
            print(i[5][j - 1], end="")
            if (j % 2 == 0):
                print(" ", end="")
        print("")
        if (i[6] != " "):
            print(i[6], end="")
        if(i[7]!=" "):
            print("zdrojová IP adresa: ", i[7])
        if(i[8]!=" "):
            print("cieľová IP adresa: ", i[8])
        if (i[9] != " "):
            print(i[9].replace("-", "").replace("_"," "), end="")
        for j in range(1, len(i[10]) + 1):
            print(i[10][j - 1], end="")
            if (j % 2 == 0):
                print("", end=" ")
            if (j % 16 == 0):
                print("", end=" ")
            if (j % 32 == 0):
                print("")
        print("")
        print("zdrojovy port: ",i[11])
        print("cielovy port: ",i[12])
        print("--------------------------------------------")

def TCP_Port(a,TCP,Vystup,Ramec):
    dlzka = a[14:15].hex()
    if (a[(16+int(dlzka[0],16)*int(dlzka[1],16)):(18+int(dlzka[0],16)*int(dlzka[1],16))].hex() in TCP.keys()):
        Ramec[-1]=Ramec[-1]+"-"+TCP[a[(16+int(dlzka[0],16)*int(dlzka[1],16)):(18+int(dlzka[0],16)*int(dlzka[1],16))].hex()]
        Vystup.write(TCP[a[(16+int(dlzka[0])*int(dlzka[1])):(18+int(dlzka[0])*int(dlzka[1]))].hex()].replace("_"," "))
    elif (a[(14+int(dlzka[0],16)*int(dlzka[1],16)):(16+int(dlzka[0],16)*int(dlzka[1],16))].hex() in TCP.keys()):
        Ramec[-1]=Ramec[-1]+"-"+TCP[a[(14 + int(dlzka[0],16) * int(dlzka[1],16)):(16 + int(dlzka[0],16) * int(dlzka[1],16))].hex()]
        Vystup.write(TCP[a[(14 + int(dlzka[0],16) * int(dlzka[1],16)):(16 + int(dlzka[0],16) * int(dlzka[1],16))].hex()].replace("_"," "))

def UDP_Port(a,UDP,Vystup,Ramec):
    dlzka = a[14:15].hex()
    if (a[(16 + int(dlzka[0],16) * int(dlzka[1],16)):(18 + int(dlzka[0],16) * int(dlzka[1],16))].hex() in UDP.keys()):
        Ramec[-1] = Ramec[-1] + "-" +UDP[a[(16 + int(dlzka[0],16) * int(dlzka[1],16)):(18 + int(dlzka[0],16) * int(dlzka[1],16))].hex()]
        Vystup.write(UDP[a[(16 + int(dlzka[0],16) * int(dlzka[1],16)):(18 + int(dlzka[0],16) * int(dlzka[1],16))].hex()])
    elif (a[(14 + int(dlzka[0],16) * int(dlzka[1],16)):(16 + int(dlzka[0],16) * int(dlzka[1],16))].hex() in UDP.keys()):
        Ramec[-1]=Ramec[-1]+"-"+UDP[a[(14 + int(dlzka[0],16) * int(dlzka[1],16)):(16 + int(dlzka[0],16) * int(dlzka[1],16))].hex()]
        Vystup.write(UDP[a[(14 + int(dlzka[0],16) * int(dlzka[1],16)):(16 + int(dlzka[0],16) * int(dlzka[1],16))].hex()])

def ICMP_types(a, ICMP, Vystup,Ramec):
    dlzka = a[14:15].hex()
    if (str(a[14+int(dlzka[0],16)*int(dlzka[1],16)]) in ICMP.keys()):
        Ramec[-1]=Ramec[-1]+"-"+ICMP[str(a[14+int(dlzka[0],16)*int(dlzka[1],16)])].replace("_"," ")
        Vystup.write(ICMP[str(a[14+int(dlzka[0],16)*int(dlzka[1],16)])].replace("_"," "))

def zistiProtokol(a,IP_Protocol, TCP, UDP, ICMP,Vystup,Ramec):
    if a[23:24].hex() in IP_Protocol.keys():
        Vystup.write(IP_Protocol[a[23:24].hex()])
        Ramec.append(IP_Protocol[a[23:24].hex()])
        if(IP_Protocol[a[23:24].hex()]=="TCP\n"):
            TCP_Port(a, TCP, Vystup,Ramec)
        if (IP_Protocol[a[23:24].hex()] == "UDP\n"):
            UDP_Port(a, UDP, Vystup,Ramec)
        if (IP_Protocol[a[23:24].hex()] == "ICMP\n"):
            ICMP_types(a, ICMP, Vystup,Ramec)
    else:
        Ramec.append(" ")
def zisti_IEEE(a,LSAP,Vystup,Ramec):
    if(a[14:16].hex().upper()=="FFFF"):
        Ramec.append("IEEE 802.3 – Raw")
        Vystup.write("IEEE 802.3 – Raw\n")
    else:
        Pomm="IEEE 802.3 LLC - "
        Vystup.write("IEEE 802.3 LLC - ")
        if a[15:16].hex() in LSAP.keys():
            Pomm+=LSAP[a[15:16].hex()]
            Ramec.append(Pomm)
            Vystup.write(LSAP[a[15:16].hex()])
        else:
            Vystup.write("\n")
            Ramec.append(" ")
def TCP_komunikacia(VsetkyRamce,typ,Porty):
    MamZaciatok,neuplna,uplna,destIP,sourceIP,seq=False,False,False,None,None,None
    UplnaKom,NeuplnaKom,DocasnePole=[],[],[]
    List_Pol={}
    UKONCENE,ukoncenePor={},0
    #print("som tu")
    for i in VsetkyRamce:
        data=i[10]
        TCPP=i[9].split("-")
        if(TCPP[0]=="TCP\n"):
            flag=format(int(data[94:96].lower(),16),'08b')
            docass=i[9].split("-")
            if str(data[72:76]) in List_Pol.keys() or str(data[68:72]) in List_Pol.keys():
                if str(data[72:76]) in List_Pol.keys():
                    heslo=str(data[72:76])
                if str(data[68:72]) in List_Pol.keys():
                    heslo=str(data[68:72])
                PoleP=List_Pol[heslo]
                PoleP.append(i)
                PoleP[-1].append(data[68:72])
                PoleP[-1].append(data[72:76])
                SEQ=List_Pol[heslo][0][14].split("_")
                if((flag[-5]=='1')and(str(int(data[84:92],16)-1) in SEQ)):
                    ind=SEQ.index(str(int(data[84:92],16)-1))
                    if(ind*2==0):
                        List_Pol[heslo][0][13]=List_Pol[heslo][0][13][0] + '1' + List_Pol[heslo][0][13][2] + List_Pol[heslo][0][13][3] + List_Pol[heslo][0][13][4] + List_Pol[heslo][0][13][5] + List_Pol[heslo][0][13][6] + List_Pol[heslo][0][13][7]
                    if(ind*2==2):
                        List_Pol[heslo][0][13]=List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+List_Pol[heslo][0][13][2]+'1'+List_Pol[heslo][0][13][4]+List_Pol[heslo][0][13][5]+List_Pol[heslo][0][13][6]+List_Pol[heslo][0][13][7]
                    if(ind*2==4):
                        List_Pol[heslo][0][13]=List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+List_Pol[heslo][0][13][2]+List_Pol[heslo][0][13][3]+List_Pol[heslo][0][13][4]+'1'+List_Pol[heslo][0][13][6]+List_Pol[heslo][0][13][7]
                    if(ind*2==6):
                        List_Pol[heslo][0][13]=List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+List_Pol[heslo][0][13][2]+List_Pol[heslo][0][13][3]+List_Pol[heslo][0][13][4]+List_Pol[heslo][0][13][5]+List_Pol[heslo][0][13][6]+'1'
                if((flag[-2])=='1'):
                    SEQ[1]=str(int(data[76:84],16))
                    List_Pol[heslo][0][14]=SEQ[0]+"_"+SEQ[1]+"_"+SEQ[2]+"_"+SEQ[3]
                    List_Pol[heslo][0][13]=List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+'1'+List_Pol[heslo][0][13][3]+List_Pol[heslo][0][13][4]+List_Pol[heslo][0][13][5]+List_Pol[heslo][0][13][6]+List_Pol[heslo][0][13][7]
                if((flag[-1])=='1'):
                    if(SEQ[2]=="-1"):
                        SEQ[2]=str(int(data[76:84],16))
                        List_Pol[heslo][0][13] = List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+List_Pol[heslo][0][13][2]+List_Pol[heslo][0][13][3]+'1'+List_Pol[heslo][0][13][5]+List_Pol[heslo][0][13][6]+List_Pol[heslo][0][13][7]
                    else:
                        SEQ[3]=str(int(data[76:84],16))
                        List_Pol[heslo][0][13] = List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+List_Pol[heslo][0][13][2]+List_Pol[heslo][0][13][3]+List_Pol[heslo][0][13][4]+List_Pol[heslo][0][13][5]+'1'+List_Pol[heslo][0][13][7]
                    List_Pol[heslo][0][14] = SEQ[0] + "_" + SEQ[1] + "_" + SEQ[2] + "_" + SEQ[3]
                if((flag[-3])=='1'):
                    List_Pol[heslo][0][13] = List_Pol[heslo][0][13][0]+List_Pol[heslo][0][13][1]+List_Pol[heslo][0][13][2]+List_Pol[heslo][0][13][3]+'1'+'1'+'1'+'1'
            if ((str(data[94:96]) == "02") and (typ == docass[-1].replace("\n",""))):
                if (data[68:72].lower() in Porty.keys()) and (Porty[data[68:72].lower()].replace("\n", "") == typ.replace("\n","")):
                    kod = data[72:76]
                else:
                    kod = data[68:72]
                SeqN = str(int(data[76:84], 16)) + "_-1_-1_-1"
                if kod in List_Pol.keys():
                    PoleP=List_Pol[kod]
                    PoleP[13]='10000000'
                    PoleP[14]=SeqN
                    PoleP.append(i)
                else:
                    PoleP = []
                    PoleP.append(i)
                    PoleP[0].append(data[68:72])
                    PoleP[0].append(data[72:76])
                    handshake = '10000000'
                    PoleP[0].append(handshake)
                    PoleP[0].append(SeqN)
                    List_Pol[str(kod)] = PoleP
            if ((str(data[72:76]) not in List_Pol.keys() and str(data[68:72]) not in List_Pol.keys())) and ((typ == docass[-1].replace("\n", ""))):
                SeqN = "-1_-1_-1_-1"
                PoleP = []
                PoleP.append(i)
                PoleP[0].append(data[68:72])
                PoleP[0].append(data[72:76])
                handshake = '00000000'
                PoleP[0].append(handshake)
                PoleP[0].append(SeqN)
                # print(len(PoleP[0]))
                if (data[68:72].lower() in Porty.keys()) and (Porty[data[68:72].lower()].replace("\n", "") == typ.replace("\n", "")):
                    kod = data[72:76]
                else:
                    kod = data[68:72]
                List_Pol[str(kod)] = PoleP

    for key,value in List_Pol.items():
        if(uplna==True)and(neuplna==True):
            break
        if(value[0][13]=="11111111"):
            #print("halooo")
            if(uplna==False):
                uplna = True
                UplnaKom=value
        else:
            #print(value[0][13][:4])
            if(value[0][13][:4]=="1111"):
                #print("hello")
                if(neuplna==False):
                    neuplna = True
                    NeuplnaKom=value
    print("\n--------------------------------------------------------\nNEUPLNA KOMUNIKACIA \n--------------------------------------------------------\n")
    vypisRamce(NeuplnaKom)
    print("\n\n---------------------------------------------------------------------------------------------------------------------------------------\n\n")
    print("\n--------------------------------------------------------\nUPLNA KOMUNIKACIA\n--------------------------------------------------------\n")
    #if('0' in UKONCENE.keys()):
        #vypisRamce(UKONCENE['0'])
    vypisRamce(UplnaKom)
    print("\n\n---------------------------------------------------------------------------------------------------------------------------------------\n\n")
    List_Pol.clear()
    UKONCENE.clear()
def TFTP_komunikacia(VsetkyRamce):
    List_Pol = {}
    for i in VsetkyRamce:
        data=i[10]
        TFTP=i[9].split("-")
        if(TFTP[0]=="UDP\n")or(TFTP[0].replace("\n","")=="ICMP"):
            if (TFTP[0].replace("\n", "") == "ICMP"):
                #print(str(data[68:70]))
                if str(data[68:70]) == "03":
                    if str(data[124:128]) in List_Pol.keys() or str(data[128:132]) in List_Pol.keys():
                        if (str(data[128:132]) in List_Pol.keys()):
                            heslo = str(data[128:132])
                        else:
                            heslo = str(data[124:128])
                        PoleP = List_Pol[heslo]
                        PoleP.append(i)
                        PoleP[-1].append(data[124:128])
                        PoleP[-1].append(data[128:132])
            if str(data[72:76]) in List_Pol.keys() or str(data[68:72]) in List_Pol.keys():
                PoleP = []
                if(str(data[72:76]) in List_Pol.keys()):
                    heslo = str(data[72:76])
                else:
                    heslo = str(data[68:72])
                PoleP = List_Pol[heslo]
                PoleP.append(i)
                PoleP[-1].append(data[68:72])
                PoleP[-1].append(data[72:76])
            else:
                if (TFTP[-1] == "TFTP\n"):
                    PoleP=[]
                    PoleP.append(i)
                    PoleP[0].append(data[68:72])
                    PoleP[0].append(data[72:76])
                    #print(str(data[68:72]),"/**/*/*/*/*/*")
                    List_Pol[str(data[68:72])]=PoleP
    increment=1
    for key,value in List_Pol.items():
        print("\n---------------------------------------TFTP-komunikacia c",increment,"---------------------------------------------\n")
        vypisRamce(value)
        increment+=1
        print("\n---------------------------------------------------------------------------------------------------------\n")
def ICMP_komunikacie(VsetkyRamce):
    ###TODO opravit
    List_Pol={}
    poradie=1
    for i in VsetkyRamce:
        IMCPS=i[9].split("-")
        data=i[10]
        if(IMCPS[0].replace("\n","")=="ICMP"):
            # print(IMCPS[0])
            print(data[68:70])
            if(str(data[68:70])=="08"):
                Pole_P=[]
                Pole_P.append(i)
                List_Pol[str(data[76:80])+str(data[80:84])]=Pole_P
            if(str(data[68:70])=="00"):
                if ((str(data[76:80])+str(data[80:84])) in List_Pol.keys()):
                    Pole_P=List_Pol[str(data[76:80])+str(data[80:84])]
                    Pole_P.append(i)
                else:
                    Pole_P=[]
                    Pole_P.append(i)
                    List_Pol[str(data[76:80])+str(data[80:84])]=Pole_P
            if(str(data[68:70])=="0B"):
                #print(data[-8:-4], data[-4:])
                if ((str(data[-8:-4])+str(data[-4:])) in List_Pol.keys()):
                    Pole_P=List_Pol[str(data[-8:-4])+str(data[-4:])]
                    Pole_P.append(i)
                else:
                    Pole_P=[]
                    Pole_P.append(i)
                    List_Pol[str(data[-8:-4])+str(data[-4:])]=Pole_P
    for key,value in List_Pol.items():
        print("\n\n--------------------------------------------------\n", poradie, ". ICMP komunikacia:\n")
        vypisCele(value, False)
        poradie += 1
        print("\n---------------------------------------------------------\n")
def ARP_dvojice(VsetkyRamce):
    List_Pol={}
    Konecne={}
    pocet=1
    for i in VsetkyRamce:
        data=i[10]
        ARPP=i[6]
        #print(ARPP)
        if(ARPP.replace("\n","")=="ARP"):
            if(data[40:44]=="0001"):
                KEY = str(data[56:64]) + "-" + str(data[76:84])
                if(KEY in List_Pol.keys()):
                    Pole_P=List_Pol[KEY]
                    poradie=Pole_P[0][-1]
                    Pole_P.append(i)
                    Pole_P[-1].append("ARP-Request")
                    Pole_P[-1].append(str(data[76:84]))
                    Pole_P[-1].append(str(data[56:64]))
                    Pole_P[-1].append(str(data[42:56]))
                    Pole_P[-1].append(str(data[76:84]))
                    Pole_P[-1].append("???")
                    Pole_P[-1].append(poradie)
                else:
                    Pole_P=[]
                    Pole_P.append(i)
                    Pole_P[-1].append("ARP-Request")
                    Pole_P[-1].append(str(data[76:84]))
                    Pole_P[-1].append(str(data[56:64]))
                    Pole_P[-1].append(str(data[42:56]))
                    Pole_P[-1].append(str(data[76:84]))
                    Pole_P[-1].append("???")
                    Pole_P[-1].append(pocet)
                    pocet+=1
                    List_Pol[KEY]=Pole_P
            if(data[40:44]=="0002"):
                KEY=str(data[76:84])+"-"+str(data[56:64])
                if (KEY in List_Pol.keys()):
                    Pole_P = List_Pol[KEY]
                    Pole_P.append(i)
                    Pole_P[-1].append("ARP-Reply")
                    Pole_P[-1].append(Pole_P[0][12])
                    Pole_P[-1].append(str(data[56:64]))
                    Pole_P[-1].append(str(data[42:56]))
                    Pole_P[-1].append(str(data[76:84]))
                    MAC = str(data[44:56])
                    #print(MAC)
                    Pole_P[-1].append(MAC[:2] + " " + MAC[2:4] + " " + MAC[4:6] + " " + MAC[6:8] + " " + MAC[8:10] + " " + MAC[10:12])
                    #print(Pole_P)
                    Konecne[str(Pole_P[0][-1])]=Pole_P
                    del List_Pol[KEY]
                else:
                    Pole_P = []
                    Pole_P.append(i)
                    Pole_P[-1].append("ARP-Reply")
                    Pole_P[-1].append(str(data[84:106]))
                    Pole_P[-1].append(str(data[56:64]))
                    Pole_P[-1].append(str(data[56:64]))
                    Pole_P[-1].append(str(data[42:56]))
                    Pole_P[-1].append(str(data[76:84]))
                    MAC=str(data[44:56])
                    Pole_P[-1].append(MAC[:2]+" "+MAC[2:4]+" "+MAC[4:6]+" "+MAC[6:8]+" "+MAC[8:10]+" "+MAC[10:12])
                    Pole_P[-1].append(pocet)
                    Konecne[str(pocet)]=Pole_P
                    pocet+=1
    KLUCE=[]
    for key,value in Konecne.items():
        KLUCE.append(int(key))
    for key,value in List_Pol.items():
        KLUCE.append(int(value[0][-1]))
        Konecne[str(value[0][-1])]=value
    KLUCE.sort()
    for i in KLUCE:
        if(str(i) in Konecne.keys()):
            print("\n---------------------------------------ARP-komunikacia c",i,"---------------------------------------------\n")
            vypisCele(Konecne[str(i)], True)
            print("")
for i in pack:
    EtherType=""
    Ramec=[]
    Ramec.clear()
    a = bytearray(i[1])
    Ramec.append(pocitadlo)
    Vystup.write("rámec: "+str(pocitadlo)+"\n")
    pocitadlo+=1
    Vystup.write("dĺžka rámca poskytnutá pcap API – ")
    Vystup.write(str(len(i[1])))
    Vystup.write("B \n")
    Ramec.append(len(i[1]))
    if(len(i[1])<=60):
        Vystup.write("dĺžka rámca prenášaného po médiu – 64 B \n")
        Ramec.append(64)
    else:
        Vystup.write("dĺžka rámca prenášaného po médiu – ")
        Vystup.write(str(len(i[1])+4))
        Vystup.write("B \n")
        Ramec.append(len(i[1])+4)
    if(int(a[12:14].hex(),16)>=1500):
        Vystup.write("Ethernet II\n")
        Ramec.append("Ethernet II")
        ETH=1
    else:
        ETH=0
        zisti_IEEE(a, LSAP,Vystup,Ramec)
    zdrojova=a[6:12].hex().upper()
    Ramec.append(zdrojova)
    Vystup.write("Zdrojová MAC adresa: ")
    for j in range(1,len(zdrojova)+1):
        Vystup.write(zdrojova[j - 1])
        if(j%2==0):
            Vystup.write(" ")
    Vystup.write("\n")
    zdrojova = a[:6].hex().upper()
    Ramec.append(zdrojova)
    Vystup.write("Cieľová MAC adresa:")
    for j in range(1,len(zdrojova)+1):
        Vystup.write(zdrojova[j-1])
        if(j%2==0):
            Vystup.write(" ")
    Vystup.write("\n")
    if a[12:14].hex() in ETHERTYPE.keys() and ETH==1:
        EtherType = ETHERTYPE[a[12:14].hex()]
        Ramec.append(EtherType)
        Vystup.write(EtherType)
    else:
        Ramec.append(" ")
    if(EtherType=="IPv4\n"):
        Vystup.write("zdrojová IP adresa: ")
        Ramec.append(str(int(a[26:27].hex(),16))+"."+str(int(a[27:28].hex(),16))+"."+str(int(a[28:29].hex(),16))+"."+str(int(a[29:30].hex(),16)))
        Vystup.write(str(int(a[26:27].hex(),16))+"."+str(int(a[27:28].hex(),16))+"."+str(int(a[28:29].hex(),16))+"."+str(int(a[29:30].hex(),16)))
        AKTip1=str(int(a[26:27].hex(),16))+"."+str(int(a[27:28].hex(),16))+"."+str(int(a[28:29].hex(),16))+"."+str(int(a[29:30].hex(),16))
        Vystup.write("\n")
        Vystup.write("cieľová IP adresa: ")
        Ramec.append(str(int(a[30:31].hex(),16))+"."+str(int(a[31:32].hex(),16))+"."+str(int(a[32:33].hex(),16))+"."+str(int(a[33:34].hex(),16)))
        Vystup.write(str(int(a[30:31].hex(),16))+"."+str(int(a[31:32].hex(),16))+"."+str(int(a[32:33].hex(),16))+"."+str(int(a[33:34].hex(),16)))
        AKTip2=str(int(a[30:31].hex(),16))+"."+str(int(a[31:32].hex(),16))+"."+str(int(a[32:33].hex(),16))+"."+str(int(a[33:34].hex(),16))
        Vystup.write("\n")
    else:
        Ramec.append(" ")
        Ramec.append(" ")
    if(ETH==1):
        zistiProtokol(a,IP_Protocol, TCP, UDP, ICMP,Vystup,Ramec)
    else:
        Ramec.append(" ")
    vypis=a.hex().upper()
    Ramec.append(vypis)
    for j in range(1,len(vypis)+1):
        Vystup.write(vypis[j-1])
        if(j%2==0):
            Vystup.write(" ")
        if(j%16==0):
            Vystup.write(" ")
        if(j%32==0):
            Vystup.write("\n")
    if(EtherType=="IPv4\n"):
        if AKTip1 in IPV_4_Miesto:
            miesto=IPV_4_Miesto.index(AKTip1)
            SPLIT=IPV_4_Info[miesto].split("-")
            SPLIT[0]=str(int(SPLIT[0])+1)
            Spojene=SPLIT[0] +"-"+ SPLIT[1]
            IPV_4_Info[miesto]=Spojene
        else:
            Pomocn="1-0"
            IPV_4_Miesto.append(AKTip1)
            IPV_4_Info.append(Pomocn)
    Vystup.write("\n\n")
    VsetkyRamce.append(Ramec)
Vystup.close()
print("Pcap subor bol analyzovany, informacie boli ulozene do vystup.txt")
max,maxMiesto,iterat=0,None,0
for i in IPV_4_Info:
    Pomocn=i.split("-")
    if(int(Pomocn[0])>max):
        max=int(Pomocn[0])
        maxMiesto=iterat
    iterat+=1
print("Zoznam IP adries vysielajucich uzlov: ")
for i in IPV_4_Miesto:
    print(i)
print("\n")
INFO=IPV_4_Info[maxMiesto].split("-")
print("Adresa uzla s najväčším počtom odoslaných paketov: ")
print(IPV_4_Miesto[maxMiesto],"       ",INFO[0],"packetov")
print("\n")
while True:
    volba=input("0. Vypise IP adresy vsetkych vysielajucich uzlov, uzol s najvacsim poctom odoslanych packetov\n"
                "1. Vypise vsetky zaznamy na konzolu\n"
                "2. Vypise HTTP komunikaciu nad TCP protokolom\n"
                "3. Vypise HTTPS komunikaciu nad TCP protokolom\n"
                "4. Vypise TELNET komunikaciu nad TCP protokolom\n"
                "5. Vypise SSH komunikaciu nad TCP protokolom\n"
                "6. Vypise FTP riadiace komunikacie nad TCP protokolom\n"
                "7. Vypise FTP datove komunikacie nad TCP protokolom\n"
                "8. Vypise TFTP komunikaciu\n"
                "9. Vypise ICMP komunikaciu\n"
                "10. Vypise ARP komunikaciu\n"
                "x. Pre ukoncenie\n")
    if volba == '0':
        print("Zoznam IP adries vysielajucich uzlov: ")
        for i in IPV_4_Miesto:
            print(i)
        print("\n")
        INFO = IPV_4_Info[maxMiesto].split("-")
        print("Adresa uzla s najväčším počtom odoslaných paketov: ")
        print(IPV_4_Miesto[maxMiesto], "       ", INFO[0], "packetov")
        print("\n")
    if volba == '1':
        vypisCele(VsetkyRamce,False)
    if volba == '2':
        TCP_komunikacia(VsetkyRamce,"HTTP",TCP)
    if volba == '3':
        TCP_komunikacia(VsetkyRamce,"HTTPS",TCP)
    if volba == '4':
        TCP_komunikacia(VsetkyRamce,"Telnet",TCP)
    if volba == '5':
        TCP_komunikacia(VsetkyRamce,"SSH",TCP)
    if volba == '6':
        TCP_komunikacia(VsetkyRamce,"FTP_riadenie",TCP)
    if volba == '7':
        TCP_komunikacia(VsetkyRamce, "FTP_data", TCP)
    if volba == '8':
        TFTP_komunikacia(VsetkyRamce)
    if volba == '9':
        ICMP_komunikacie(VsetkyRamce)
    if volba == '10':
        ARP_dvojice(VsetkyRamce)
    if volba == 'x':
        exit(1)

