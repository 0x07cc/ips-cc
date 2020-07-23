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
    def __init__(self, logfile, time_start=time.time()):
        if (time_start == None):
            time_start = time.time()
        self.time_start = time_start
        
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S") # Time String
        
        # Prova ad aprire il file di logging.
        # Se non riesce stampa un errore.
        try:
            self.logfile = open(logfile,"a")
        except:
            print("[" + ts + "]: Error while opening logfile.")
            #TODO: meglio uscire se non riesce?
        
        self.logfile.write("[" + ts + "]: Starting Log session\n")

    # Funzione di Update Log (Aggiornamento Log):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale
    # (datetime.now)
    def uplog(self, s):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        print("[" + ts + "]: " + s + "\n")
        self.logfile.write("[" + ts + "]: "+ s +"\n")

    # Funzione di Relative Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo
    # relativo dall'avvio del logging.
    def rt_uplog(self, s): #relative time uplog
        s = str(s)
        rts = "[%.3f]: " + s + "\n"             # relative time string
        print(rts % (time.time() - self.time_start)) 
        self.logfile.write(rts % (time.time() - self.time_start))

    # Funzione di No Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro, senza
    # indicazioni sul tempo.
    def nt_uplog(self,s): #no time uplog
        s = str(s)
        print(s)
        self.logfile.write(s + "\n")

    # Funzione di chiusura logging:
    # Appende nel file una linea di
    # terminazione e lo chiude.
    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")      
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n")
        self.logfile.close()
