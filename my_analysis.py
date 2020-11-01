# Analysis Module
# Kowalski, Analysis!
import re


class Shield:

    # Metodo costruttore dell'oggetto.
    # Data in input una lista di stringhe che definisce le parole chiave
    # "pericolose" tramite regex, costruisce la lista di regex compilate
    # che verranno usate nell'analisi dei pacchetti (self.compiled_regex).
    # Riceve in input inoltre una stringa che definisce il tipo di servizio
    # e un oggetto di classe Log.
    # Le regex in input sono stringhe, mentre le regex compilate sono byte:
    # questo permette di effettuare il matching col payload (byte) ricevuto.
    def __init__(self, regex_list, service_type, log):
        self.regex_list = regex_list
        self.service_type = service_type
        self.log = log
        self.rules = None
        self.compiled_regex = []
        for r in regex_list:
            self.compiled_regex.append(re.compile(r.encode()))
            log.uplog("Regex added: " + r)
        log.uplog("Service type: " + self.service_type)

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

    # TODO doc
    # Le rules vengono usate in UTILS! Funzione genera_argomenti
    def set_rules(self, iptables_list, nfqueue):
        # TODO che succede se e' None e la funzione ritorna senza settare?
        if iptables_list is None:
            return

        rules = {}
        # Creo una lista contenente ogni riga della lista iptables
        lista = iptables_list.split("\n")
        lista2 = []

        stringa_cercare = "NFQUEUE num " + str(nfqueue)

        # Ricerca riga per riga
        for riga in lista:
            if riga.find(stringa_cercare) != -1:
                lista2.append(riga)

        # In lista2 ci sono tutte le regole destinate a NFQUEUE
        for riga2 in lista2:
            # Verifico se la regola e' in uscita
            trovato = re.search("spt:(\d)+", riga2)
            if trovato is not None:
                porta = int(riga2[trovato.start() + 4:trovato.end()])
                rules[porta] = "OUTPUT"
            else:
                # Verifico se la regola e' in ingresso
                trovato = re.search("dpt:(\d)+", riga2)
                if trovato is not None:
                    porta = int(riga2[trovato.start() + 4:trovato.end()])
                    rules[porta] = "INPUT"
                else:
                    self.log.uplog("Error while parsing iptables rules list")
        self.log.uplog("RULES: " + str(rules))
        self.rules = rules
