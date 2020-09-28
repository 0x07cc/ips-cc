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
    def __init__(self, logfile="logfile.log", time_start=time.time(), erase_old_logfile=False, debug_mode=False):
        if (time_start == None):
            time_start = time.time()
        self.time_start = time_start

        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S") # Time String

        # Prova ad aprire il file di logging.
        # Se non riesce stampa un errore.
        try:
            if erase_old_logfile:
                self.logfile = open(logfile,"w")
            else:
                self.logfile = open(logfile,"a")
        except:
            print("[" + ts + "]: Error while opening logfile.")
            #TODO: meglio uscire se non riesce?

        self.logfile.write("[" + ts + "]: Starting Log session\n\n")
        self.debug_mode = debug_mode

    # Funzione di Update Log (Aggiornamento Log):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale (datetime.now).
    # new_line descrive il numero di \n da concatenare
    #alla stringa in input (default 1).
    def uplog(self, s, new_line=1, color = "None",bold=0):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        log_s = "[" + ts + "]: " + s + "\n"*new_line # la print aggiunge un \n di suo, ma a schermo va bene
        self.logfile.write("["+ts+"]: "+ s +"\n"*new_line)

        if(color != None or bold !=0):  # Colore della stringa di log https://ozzmaker.com/add-colour-to-text-in-python/
            if color == None:
                log_s = "\033["+str(bold)+";37;40m"+log_s+"\033[0;37;40m"
            elif color == "red":
                log_s = "\033["+str(bold)+";31;40m"+log_s+"\033[0;37;40m"
            elif color == "yellow":
                log_s = "\033["+str(bold)+";33;40m"+log_s+"\033[0;37;40m"
            elif color == "cyan":
                log_s = "\033["+str(bold)+";36;40m"+log_s+"\033[0;37;40m"
        print(log_s)


    # Funzione di Relative Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo
    # relativo dall'avvio del logging.
    # new_line descrive il numero di \n da concatenare
    #alla stringa in input (default 1).
    def rt_uplog(self, s, new_line=1): #relative time uplog
        s = str(s)
        rts = "[%.3f]: " + s + "\n"*new_line             # relative time string
        print(rts % (time.time() - self.time_start))
        self.logfile.write(rts % (time.time() - self.time_start))

    # Funzione di No Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro, senza
    # indicazioni sul tempo.
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def nt_uplog(self,s,new_line=1): #no time uplog
        s = str(s)
        print(s+'\n'*(new_line-1))
        self.logfile.write(s + "\n"*new_line)

    # Funzione di Only File Update Log (Aggiornamento Log):
    # Stampa solo nel file di log la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale
    # (datetime.now)
    # new_line descrive il numero di \n da concatenare
    #alla stringa in input (default 1).
    def of_uplog(self, s, new_line=1):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  
        self.logfile.write("["+ts+"]: "+ s +"\n"*new_line)

    '''# TODO: general purpose log function
    def log(self, s, new_line=1, time_mode=0):
        if (time_mode==0):
            if self.debug_mode:
                uplog(self, s, new_line)
            else:
                of_uplog(self, s, new_line) # No, metter una funzione che logga solo i pacchetti droppati
        elif (time_mode==1):

    '''

    # Funzione di chiusura logging:
    # Appende nel file una linea di terminazione e lo chiude.
    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n\n\n\n")
        self.logfile.close()
