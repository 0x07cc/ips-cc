# Analysis Module
# Kowalski, Analysis!

import re


# Classe Shield, definisce gli 
class Shield:


    # Funzione costruttore dell'oggetto.
    # Data in input una lista di stringhe che definisce
    # le parole chiave "pericolose" tramite regex,
    # costruisce la lista di regex compilate che verranno
    # usate nell'analisi dei pacchetti.
    # service_type è una variabile che definisce il tipo di servizio,
    # inoltre ottiene dal main l'oggetto log per accedervi.
    def __init__(self, regex_list, service_type, log):
        log.uplog("Generating Shield object:",1)
        self.regex_list = regex_list
        self.compiled_regex = []
        for r in regex_list:
            self.compiled_regex.append(re.compile(r.encode()))
            log.uplog("Regex added: "+r)#+"   "+str(self.compiled_regex[-1]))
        self.service_type = service_type
        log.uplog("Service type: "+self.service_type,2)
        self.log = log


    # Funzione che controlla il matching di una delle regex 
    # presenti nella regex_list (e in forma compilata in
    # compiled regex ). 
    # Se matcha -> True, altrimenti False
    def regex_trigger(self, payload):
        for cr in self.compiled_regex:
            if (cr.search(payload)):
                return True
        return False

    # Funzione che determina se un pacchetto è da droppare.
    # Se ingore_TCP_parameters è settato a True la ricerca ignora
    # i primi 52 Bytes del pacchetto 
    def is_droppable(self, payload, ingore_TCP_parameters=True):
        if (ingore_TCP_parameters):
            payload = payload[52:]
        if (self.regex_trigger(payload)):
            return True
        # elif (...), aggiungere qui altre funzioni che possono determinare il drop
        #   return True
        return False

''' Versione successiva, per ora inutile

    # Funzione che determina se un pacchetto è da droppare.
    # Se only_Data è settato a True la ricerca viene fatta 
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

    # Funzione che estrae dal payload i dati su cui è utile 
    # fare l'analisi. A determinare il tipo di estrazione e
    # raffinazione è l'attributo service_type
    def digest(self, payload):
        if (self.service_type == 'Netcat'):  # Ovviamente questo è solo per esempio, non ci sarà una if 
            payload = payload[52:]           # per ogni servizio possibile, la variabile service_type
        return payload                       # sarà fatta in modo tale da permettere una classificazione generica
'''
    


