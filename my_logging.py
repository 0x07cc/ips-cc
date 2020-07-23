# Logging module
import time
from datetime import datetime

class Log:

    # Funzione costruttore dell'oggetto.
    # Il logging ha inizio dal time passato
    # tramite parametro. Se non e' stato
    # passato, ha inizio da time.time().
    # Apre il file passatogli tramite parametro
    # e vi appende una linea iniziale.
    def __init__(self, logfile="logfile.log", time_start=time.time()):
        if (time_start == None):
            time_start = time.time()
        self.time_start = time_start
        self.logfile = open(logfile,"a") # TODO: aggiungere Try
        now = datetime.now()
        self.logfile.write("["+now.strftime("%d/%m/%Y %H:%M:%S")+"]: Starting Log session\n")

    # Funzione di Update Log (Aggiornamento Log):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale
    # (datetime.now)
    # new_line descrive il numero di \n da concatenare alla stringa in input
    # (default 1)
    def uplog(self, s, new_line=1):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        print("[" + ts + "]: " + s + "\n"*new_line) # la print aggiunge un \n di suo, ma a schermo va bene
        self.logfile.write("["+ts+"]: "+ s +"\n"*new_line)

    # Funzione di Relative Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo
    # relativo dall'avvio del logging.
    # new_line descrive il numero di \n da concatenare alla stringa in input
    # (default 1)
    def rt_uplog(self, s, new_line=1): #relative time uplog
        s = str(s)
        rts = "[%.3f]: " + s + "\n"*new_line             # relative time string
        print(rts % (time.time() - self.time_start)) 
        self.logfile.write(rts % (time.time() - self.time_start))

    # Funzione di No Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro, senza
    # indicazioni sul tempo.
    # new_line descrive il numero di \n da concatenare alla stringa in input
    # (default 1)
    def nt_uplog(self,s,new_line=1): #no time uplog
        s = str(s)
        print(s+'\n'*(new_line-1))
        self.logfile.write(s + "\n"*new_line)

    # Funzione di chiusura logging:
    # Appende nel file una linea di
    # terminazione e lo chiude.
    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")      
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n")
        self.logfile.close()
