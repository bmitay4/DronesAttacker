import os
import time
from threading import Thread
from tkinter import *
import pandas
import psutil
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
from scapy.sendrecv import sniff

myFont = ("Tahoma", 11)


class DronesTaker:
    def __init__(self):
        self.root = Tk(className="DronesTaker")
        self.network_card = StringVar(value=None)
        self.attack_card = StringVar(value=None)
        self.drone_ssid = StringVar(value=None)
        self.Tree = None
        self.itemList = []
        self.drone_options = OptionMenu(self.root, self.drone_ssid, "Pick a drone")

    def conf(self):
        self.root.title("DronesTaker Module")
        self.root.geometry("560x260+480+250")
        self.root.resizable(width=False, height=False)
        iconPic = PhotoImage(file='src/ev')
        self.root.iconphoto(True, iconPic)
        self.root.option_add('*Dialog.msg.font', 'Tahoma 10')

        network_card = "Choose a network interface"
        drone_picker = "Choose a drone to attack"
        attack_type = "Choose an attack type"

        choices = psutil.net_if_addrs()

        Label(self.root, text=network_card, font=myFont).place(x=5, y=10)
        Label(self.root, text=attack_type, font=myFont).place(x=5, y=45)
        Label(self.root, text=drone_picker, font=myFont).place(x=5, y=85)
        Button(self.root, text="Scan", command=self.set_card, width=7, height=3, font=myFont).place(x=460, y=6)

        card_options = OptionMenu(self.root, self.network_card, *choices)
        card_options.config(width=21, font=myFont)
        card_options.place(x=220, y=5)
        # self.network_card.trace_add("write", callback=self.set_card)

        attack_options = OptionMenu(self.root, self.attack_card, "Deauthentication packets", "ICMP")
        attack_options.config(width=21, font=myFont)
        attack_options.place(x=220, y=40)

    def set_card(self, *args):
        self.set_monitor_mode()
        scanObj = WiFiScan(self.network_card.get())
        scanObj.run()
        scanData = scanObj.getAPs()
        for row in scanData.itertuples():
            self.itemList.append([row.Index, row.SSID, row.dBm_Signal])
        self.drone_options = OptionMenu(self.root, self.drone_ssid, *self.itemList)
        self.drone_options.config(width=32, font=myFont)
        self.drone_options.place(x=220, y=80)

    def set_monitor_mode(self):
        os.system("ifconfig " + self.network_card.get() + " down")
        os.system("iwconfig " + self.network_card.get() + " mode monitor")
        os.system("ifconfig " + self.network_card.get() + " up")

    def run(self):
        self.conf()
        self.root.mainloop()


class WiFiScan:
    def __init__(self, interface):
        self.interface = interface
        self.networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        self.networks.set_index("BSSID", inplace=True)

    def callback(self, packet):
        if packet.haslayer(Dot11Beacon):
            # extract the MAC address of the network
            myBSSID = packet[Dot11].addr2
            # get the name of it
            mySSID = packet[Dot11Elt].info.decode()
            if len(mySSID) == 0:
                mySSID = "Hidden Network Detected"
            try:
                mySignal = packet.dBm_AntSignal
            except:
                mySignal = "N/A"
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            myChannel = stats.get("channel")
            # get the crypto
            myCrypto = stats.get("crypto")
            self.networks.loc[myBSSID] = (mySSID, mySignal, myChannel, myCrypto)

    def change_channel(self):
        timeout = 12
        ch = 1
        while timeout > 0:
            os.system(f"iwconfig {self.interface} channel {ch}")
            # switch channel from 1 to 14 each 0.5s
            ch = ch % 14 + 1
            time.sleep(0.5)
            timeout = timeout - 1

    def getAPs(self):
        return self.networks.sort_values(by='dBm_Signal', ascending=False)

    def run(self):
        channel_changer = Thread(target=self.change_channel)
        channel_changer.daemon = True
        channel_changer.start()

        sniff(prn=self.callback, iface=self.interface, timeout=10)


if __name__ == '__main__':
    myObj = DronesTaker()
    myObj.run()
