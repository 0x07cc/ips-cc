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
    def __init__(self, logfile="logfile.log", level="INFO", time_start=time.time(), erase_old_logfile=False): 
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
                self.logfile.write("[" + ts + "]: Erasing old Log session\n\n")
            else:
                self.logfile = open(logfile,"a")

            self.logfile.write("[" + ts + "]: Starting Log session\n\n")
        except:
            print("\033[1;33;40m[" + ts + "] WARN: Error while opening logfile.\033[0;37;40m")
            
            # TODO: meglio uscire se non riesce? uplog funziona anche se non scrivo sul file (da warning però)
            # exit(-1)
        
        # Dictionary of log levels
        self.level_dict={   "ALL":      0,   # Gotta log 'em all
                            "DEBUG":    1,   # Logs debug messages
                            "INFO":     2,   # Logs info about progress of the service
                            "WARN":     3,   # Logs potentially unwanted or harmfull situations
                            "DEFENCE":  4,   # Custom Level. Logs packets dropped by the IPS or notable external causes
                            "ERROR":    5,   # Logs error events that might still allow the application to continue running
                            "FATAL":    6    # Shit get real. Abort of service
                        }

        self.level=self.level_dict[level]    # Level Treshold of logger

    

    
    # Funzione di Log (log a livelli):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale (datetime.now).
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    # La stringa viene loggata solo se il suo livello
    # è maggiore o uguale a quello settato alla creazione
    # dell'oggetto log.
    def uplog(self, s, level="INFO", new_line=1):

        try:
            act_level = self.level_dict[level]
        except:
            level = "ALL"
            act_level = 0
            self.uplog("Wrong log level setted for string:\n"+s,"DEBUG")
            

        if  act_level < self.level:                             # If the actual logging level is < of the setted level 
            return                                              # the function return

        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")                  # time string
        if(act_level > 2):                                      # print Level if > INFO
            log_s = "["+ts+"] "+level+": " + s 
        else:
            log_s = "["+ts+"]: " + s      

        try:                                                    # Log on file
            self.logfile.write(log_s+"\n")                      # If failed a warn is added to the string (independently from the
        except:                                                 # trashold level). If it is going to be printed it is important!
            log_s = log_s+"\n[WARN: Unable to write on Logfile]"   

        log_s += "\n"*new_line 

        if level == "ALL":                                      # Color of the logging string   
            clog_s = log_s                                      # https://ozzmaker.com/add-colour-to-text-in-python/
        elif level == "DEBUG":
            clog_s = "\033[0;32;40m"+log_s+"\033[0;37;40m"  # Green   
        elif level == "INFO":
            clog_s = log_s
            #clog_s = "\033[1;37;40m"+log_s+"\033[0;37;40m" # Bold neutral
        elif level == "WARN":
            clog_s = "\033[1;33;40m"+log_s+"\033[0;37;40m"  # Yellow (bold)
        elif level == "DEFENCE":
            clog_s = "\033[1;36;40m"+log_s+"\033[0;37;40m"  # Cyan (bold)
        elif level == "ERROR":
            clog_s = "\033[1;31;40m"+log_s+"\033[0;37;40m"  # Red (bold)
        elif level == "FATAL":
            clog_s = "\033[1;37;41m"+log_s+"\033[0;37;40m"  # White on red (bold)

        print(clog_s)                                           # print on console





    # Funzione di custom update Log (Aggiornamento Log customizzato):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale (datetime.now).
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    # bold definisce se la stringa deve essere maiuscola mentre
    # color definisce il colore (tra quelli implmentati)
    def cust_uplog(self, s, new_line=1, color = "None",bold=0):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        log_s = "[" + ts + "]: " + s + "\n"*new_line # la print aggiunge un \n di suo, ma a schermo va bene
        
        try:
            self.logfile.write("["+ts+"]: "+ s +"\n"*new_line)
        except:
            self.uplog("Error while opening logfile","DEBUG")

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
        try:
            self.logfile.write(s + "\n"*new_line)
        except:
            self.uplog("Error while opening logfile","DEBUG")

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


    # Funzione di chiusura logging:
    # Appende nel file una linea di terminazione e lo chiude.
    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n\n\n\n")
        self.logfile.close()
