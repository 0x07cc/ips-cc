# Analysis Module
# Kowalski, Analysis!
import re

class Shield:

    # Funzione costruttore dell'oggetto.
    # Data in input una lista di stringhe che definisce
    # le parole chiave "pericolose" tramite regex,
    # costruisce la lista di regex compilate che verranno
    # usate nell'analisi dei pacchetti.
    # service_type e' una variabile che definisce il tipo di servizio,
    # inoltre ottiene dal main l'oggetto Log per accedervi.
    def __init__(self, regex_list, service_type, log, iptables_list=None):
        log.uplog("Generating Shield object:",1)
        self.regex_list = regex_list
        self.compiled_regex = []
        for r in regex_list:
            self.compiled_regex.append(re.compile(r.encode()))
            log.uplog("Regex added: "+r)#+"   "+str(self.compiled_regex[-1]))
        self.service_type = service_type
        log.uplog("Service type: " + self.service_type,2)
        self.log = log
        self.rules = None

    # Funzione che effettua il matching di una delle regex
    # presenti nella regex_list (e in forma compilata in
    # compiled_regex).
    # Se matcha -> True, altrimenti False
    def regex_trigger(self, payload):
        for cr in self.compiled_regex:
            if (cr.search(payload)):
                return True
        return False

    # Funzione che determina se un pacchetto e' da droppare.
    # Se ignore_TCP_parameters e' settato a True la ricerca ignora
    # i primi dim_header Bytes del pacchetto.
    def is_droppable(self, payload, ignore_TCP_parameters=True, dim_header=52):
        if (ignore_TCP_parameters):
            payload = payload[dim_header:]

        if (self.regex_trigger(payload)):
            return True
        # elif (...), aggiungere qui altre funzioni che possono determinare il drop
        #   return True
        return False

    def set_rules(self, iptables_list, nfqueue): 
        if iptables_list == None:
            return

        rules = {}
        # Creo una lista riga per riga
        lista = iptables_list.split("\n")
        lista2 = []

        stringa_cercare =  "NFQUEUE num " + str(nfqueue)

        # Ricerca riga per riga
        for riga in lista:
            if riga.find(stringa_cercare) != -1:
                lista2.append(riga)

        # In lista2 ci sono tutte le regole dell'NFQUEUE
        for riga2 in lista2:
            trovato = re.search("spt:(\d)+", riga2)
            if trovato is not None:
                porta = int(riga2[trovato.start()+4:trovato.end()])
                rules[porta] = "OUTPUT"
            else:
                trovato = re.search("dpt:(\d)+", riga2)
                if trovato is not None:
                    porta = int(riga2[trovato.start()+4:trovato.end()])
                    rules[porta] = "INPUT"
                else:
                    log.uplog("Qualcosa non va...")
        print("RULES: "+str(rules))
        self.rules = rules

''' Versione successiva, per ora inutile

    # Funzione che determina se un pacchetto e' da droppare.
    # Se only_Data e' settato a True la ricerca viene fatta 
    # sul digest del payload (ad esempio ignorando i primi
    # 52 Bytes del pacchetto TCP)

    def is_droppable(self, payload, only_Data=True):
        if (only_Data):
            payload = digest(payload)
        if (self.regex_trigger(payload)):
            return True
        # elif (...), aggiungere qui altre funzioni che possono determinare il drop
        #   return True
        return False

    # Funzione che estrae dal payload i dati su cui e' utile 
    # fare l'analisi. A determinare il tipo di estrazione e
    # raffinazione e' l'attributo service_type
    def digest(self, payload):
        if (self.service_type == 'Netcat'):  # Ovviamente questo e' solo per esempio, non ci sarà una if 
            payload = payload[52:]           # per ogni servizio possibile, la variabile service_type
        return payload                       # sarà fatta in modo tale da permettere una classificazione generica
'''


        