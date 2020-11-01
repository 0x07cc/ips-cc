# Logging module
import time
from datetime import datetime


class Log:

    # Metodo costruttore dell'oggetto.
    # Il logging ha inizio dal time passato
    # tramite parametro. Se non e' stato
    # passato, ha inizio da time.time().
    # Apre il file passatogli tramite parametro
    # e vi appende una linea iniziale.
    def __init__(self, logfile="logfile.log", time_start=time.time(), erase_old_logfile=False):
        if time_start is None:
            time_start = time.time()
        self.time_start = time_start

        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # Time String

        # Prova ad aprire il file di logging.
        # Se non riesce stampa un errore.
        try:
            if erase_old_logfile:
                self.logfile = open(logfile, "w")
            else:
                self.logfile = open(logfile, "a")
        except OSError:
            print("[" + ts + "]: Error while opening logfile.")

        self.logfile.write("[" + ts + "]: Starting Log session\n")

    # Metodo di Update Log (Aggiornamento Log):
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale (datetime.now).
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def uplog(self, s, new_line=1):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        print("[" + ts + "]: " + s + "\n" * new_line)
        self.logfile.write("[" + ts + "]: " + s + "\n" * new_line)

    # Metodo di Relative Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo
    # relativo dall'avvio del logging.
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def rt_uplog(self, s, new_line=1):
        s = str(s)
        rts = "[%.3f]: " + s + "\n" * new_line           # relative time string
        print(rts % (time.time() - self.time_start))
        self.logfile.write(rts % (time.time() - self.time_start))

    # Metodo di No Time Update Log:
    # Stampa a video e nel file la stringa
    # passatagli via parametro, senza
    # indicazioni sul tempo.
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def nt_uplog(self, s, new_line=1):
        s = str(s)
        print(s + '\n' * (new_line - 1))
        self.logfile.write(s + "\n" * new_line)

    # Metodo di Only File Update Log (Aggiornamento Log):
    # Stampa solo nel file di log la stringa
    # passatagli via parametro preceduta da
    # una time string basata sul tempo reale
    # (datetime.now)
    # new_line descrive il numero di \n da concatenare
    # alla stringa in input (default 1).
    def of_uplog(self, s, new_line=1):
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: " + s + "\n" * new_line)

    # Metodo di chiusura logging:
    # Appende nel file una linea di terminazione e lo chiude.
    def endlog(self):
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n\n\n\n")
        self.logfile.close()
