# Analysis Module
# Kowalski, Analysis!
import re


class Shield:

    # Metodo costruttore dell'oggetto.
    # Data in input una lista di stringhe che definisce le parole chiave
    # "pericolose" tramite regex, costruisce la lista di regex compilate
    # che verranno usate nell'analisi dei pacchetti (self.compiled_regex).
    # Riceve in input inoltre un oggetto di classe Log.
    # Le regex in input sono stringhe, mentre le regex compilate sono byte:
    # questo permette di effettuare il matching col payload (byte) ricevuto.
    def __init__(self, regex_list, log):
        self.regex_list = regex_list
        self.log = log
        self.rules = None
        self.compiled_regex = []
        for r in regex_list:
            self.compiled_regex.append(re.compile(r.encode()))
            log.uplog("Regex added: " + r)

    # Metodo che effettua il matching della stringa di byte payload
    # ricevuta in input con tutte le regex presenti in compiled_regex).
    # Se c'e' almeno un match ritorna True, altrimenti False.
    def regex_trigger(self, payload):
        for cr in self.compiled_regex:
            if (cr.search(payload)):
                return True
        return False

    # Metodo che determina se un pacchetto e' da droppare, in base
    # alla stringa di byte payload ricevuta in input.
    # Se ignore_TCP_parameters e' settato a True la ricerca ignora
    # i primi dim_header bytes del pacchetto.
    def is_droppable(self, payload, ignore_TCP_parameters=True, dim_header=52):
        if (ignore_TCP_parameters):
            payload = payload[dim_header:]

        if (self.regex_trigger(payload)):
            return True
        return False
