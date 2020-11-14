"""Logging module"""
import time
from datetime import datetime


class Log:

    def __init__(self, logfile="logfile.log",
                 time_start=time.time(), erase_old_logfile=False):
        """ Metodo costruttore dell'oggetto.

            Il logging ha inizio dal time passato tramite parametro.
            Se non e' stato passato, ha inizio da `time.time()`.

            Apre il file passatogli tramite parametro
            e vi appende una linea iniziale.

            Args:
                logfile (str): The name of the file where the log will be stored.
                time_start (float): Starting time of the logging.
                erase_old_logfile (bool): if `True` the content of `logfile` will be destroyed, otherwise the logger will append data to the file.
        """
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
                self.logfile.write("[" + ts + "]: Erasing old Log session\n")
            else:
                self.logfile = open(logfile, "a")

            self.logfile.write("[" + ts + "]: Starting Log session\n")
        except OSError:
            print("[" + ts + "]: Error while opening logfile.")

    def uplog(self, s, new_line=1):
        """ Metodo di Update Log (Aggiornamento Log):

            Stampa a video e nel file la stringa
            passatagli via parametro preceduta da
            una time string basata sul tempo reale (datetime.now).

            Args:
                s (str): The string to be logged.
                new_line (int): amount of `\\n` that will be concatenated to `s`.

            Example:
                >>> log = Log()
                >>> log.uplog("test")
                [14/11/2020 00:28:42]: test
        """
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")  # time string
        print("[" + ts + "]: " + s + "\n" * new_line)
        self.logfile.write("[" + ts + "]: " + s + "\n" * new_line)

    def rt_uplog(self, s, new_line=1):
        """ Metodo di Relative Time Update Log:

            Stampa a video e nel file la stringa passatagli via parametro
            preceduta da una time string basata sul tempo
            relativo dall'avvio del logging.

            Args:
                s (str): The string to be logged.
                new_line (int): amount of `\\n` that will be concatenated to `s`.

            Example:
                >>> log = Log()
                >>> log.rt_uplog("test")
                [9.145]: test
        """
        s = str(s)
        rts = "[%.3f]: " + s + "\n" * new_line           # relative time string
        print(rts % (time.time() - self.time_start))
        self.logfile.write(rts % (time.time() - self.time_start))

    def nt_uplog(self, s, new_line=1):
        """ Metodo di No Time Update Log:

            Stampa a video e nel file la stringa passatagli via parametro,
            senza indicazioni sul tempo.

            Args:
                s (str): The string to be logged.
                new_line (int): amount + 1 of `\\n` that will be concatenated to `s`.
        """
        s = str(s)
        print(s + '\n' * (new_line - 1))
        self.logfile.write(s + "\n" * new_line)

    def of_uplog(self, s, new_line=1):
        """ Metodo di Only File Update Log (Aggiornamento Log):

            Stampa solo nel file di log la stringa passatagli
            via parametro preceduta da una time string
            basata sul tempo reale (datetime.now).

            Args:
                s (str): The string to be logged to file.
                new_line (int): amount of `\\n` that will be concatenated to `s`.
        """
        s = str(s)
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: " + s + "\n" * new_line)

    def endlog(self):
        """ Metodo di chiusura logging:
            Appende nel file una linea di terminazione e lo chiude.
        """
        now = datetime.now()
        ts = now.strftime("%d/%m/%Y %H:%M:%S")
        self.logfile.write("[" + ts + "]: Log session has been stopped")
        self.logfile.write("\n\n\n\n\n")
        self.logfile.close()
