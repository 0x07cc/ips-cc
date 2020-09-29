# Analysis Module
# Kowalski, Analysis!
import re


# This class define the object Service, whos fields describe the port, type and rule applied.
# This last field implies that different rules (input/output) are represented by different objects.
class Service:

    def __init__(self, port, regex_list, log, service_type="Raw", firewall_direction="INPUT"):
        self.firewall_direction = firewall_direction
        self.service_type = service_type
        self.regex_list = regex_list
        self.port = port




class Shield:

    # Metodo costruttore dell'oggetto.
    # Data in input un insieme di liste di stringhe che 
    # definiscono le parole chiave "pericolose" tramite regex,
    # costruisce un dizionario contenente le liste di regex 
    # compilate per ogni servizio che verranno
    # usate nell'analisi dei pacchetti.
    # service_type e' un dizionario che definisce il tipo di 
    # servizio per ogni porta data.
    # Il campo services è un dizionario di oggetti Service, 
    # con le stesse chiavi del campo regex_list.
    # inoltre ottiene dal main l'oggetto Log per accedervi.

    def __init__(self, regex_list, services_type, log, rules=None,services=None):
        log.uplog("Generating Shield object:","INFO",1)
        self.log = log
        self.regex_list = regex_list
        self.compiled_regex = {}
        self.set_compiled_regex(regex_list)
        self.services = services
        self.services_type = services_type
        #self.stampa_services() già stampato in set_services



    # Costruisce il dizionario che fornisce le regex 
    # compilate per ogni servizio dato.
    def set_compiled_regex(self, regex_list):
        self.compiled_regex = {}
        for s in regex_list:
            self.log.cust_uplog("Service "+s,0,None,1)
            self.compiled_regex[s]=[]
            for r in regex_list[s]:
                self.compiled_regex[s].append(re.compile(r.encode()))
                self.log.uplog("Regex added: "+r,"INFO",0)
            self.log.nt_uplog("\n")


    # Funzione che effettua il matching di una delle regex
    # presenti nella regex_list (e in forma compilata in
    # compiled_regex).
    # Se matcha -> True, altrimenti False.
    # Se il servizio non è fornito (None) fa un controllo
    # del payload usando tutte le regex del dizionario.
    def regex_trigger(self, payload, service):
        if(service == None):
            for k in self.compiled_regex:
                for cr in self.compiled_regex[k]:
                    if (cr.search(payload)):
                        return True
            return False

        for cr in self.compiled_regex[service]:
            if (cr.search(payload)):
                return True
        return False

    # Funzione che determina se un pacchetto e' da droppare.
    # Se ignore_TCP_parameters e' settato a True la ricerca ignora
    # i primi dim_header Bytes del pacchetto. 
    def is_droppable(self, payload, dim_header=52, service=None, ignore_TCP_parameters=True): 
    
        if (ignore_TCP_parameters):
            payload = payload[dim_header:]

        if (self.regex_trigger(payload,service)):
            return True
        # elif (...), aggiungere qui altre funzioni che possono determinare il drop
        #   return True
        return False


    # Data in input il risultato (stringa) del comando
    # iptables -L -n, e la queue su cui lavora il net-filter,
    # costruisce il dizionario di oggetti Service.
    # Se non sono specificate le regex l'ips si spegne e avverte
    # dell'errore, mentre se a non essere specificato è il tipo
    # di serivzio allora l'ips avverte e lo setta di default "Raw"
    def set_services(self, iptables_list, nfqueue):  
        if iptables_list == None:
            return

        services = {}
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
                firewall_direction = "OUPUT"
                try:
                    services['O-'+str(porta)]=Service(porta,self.regex_list['O-'+str(porta)],self.services_type[porta],self.log,firewall_direction)
                except KeyError as e:
                        if('I-'+str(porta) in str(e)):
                            #KILLA TUTTO
                            self.log.uplog("Can't find IPTables rule for "+str(porta)+" in "+firewall_direction,"FATAL")
                            exit(-1)
                            #services['O-'+str(porta)]=Service(porta,None,self.services_type[porta],self.log,firewall_direction)
                        elif(str(porta) in str(e)):
                            self.log.uplog("Can't find service type of "+str(porta)+" in "+firewall_direction+" ... setted as Raw by deafult","WARN")
                            services['O-'+str(porta)]=Service(porta,self.regex_list['O-'+str(porta)],"Raw",self.log,firewall_direction)

            else:
                trovato = re.search("dpt:(\d)+", riga2)
                if trovato is not None:
                    porta = int(riga2[trovato.start()+4:trovato.end()])
                    firewall_direction = "INPUT"
                    try:
                        services['I-'+str(porta)]=Service(porta,self.regex_list['I-'+str(porta)],self.services_type[porta],self.log,firewall_direction)
                    except KeyError as e:
                        if('I-'+str(porta) in str(e)):
                            #KILLA TUTTO
                            self.log.uplog("Can't find IPTables rule for "+str(porta)+" in "+firewall_direction,"FATAL")
                            exit(-1)
                            #services['I-'+str(porta)]=Service(porta,None,self.services_type[porta],self.log,firewall_direction)
                        elif(str(porta) in str(e)):
                            self.log.uplog("Can't find service type of "+str(porta)+" in "+firewall_direction+" ... setted as Raw by deafult","WARN")
                            services['I-'+str(porta)]=Service(porta,self.regex_list['I-'+str(porta)],"Raw",self.log,firewall_direction)

                else:
                    log.uplog("Qualcosa non va...regola IPtables sbagliata o porta non specificata?","ERROR")
        #print("RULES: "+str(services))
        self.services = services
        self.stampa_services()


    # Stampa il tipo di servizio su ogni porta
    def stampa_services(self):
        for i in self.services_type:
            self.log.uplog("Port " +str(i)+" Service " + self.services_type[i])
        print("\n")
        return



''' Versione successiva, per ora inutile

    # Funzione che determina se un pacchetto e' da droppare.
    # Se only_Data e' settato a True la ricerca viene fatta 
    # sul digest del payload (ad esempio ignorando i primi
    # 52 Bytes del pacchetto TCP)

    def is_droppable(self, payload, only_Data=True, dim_header=52):
        if (only_Data):
            payload = digest(payload, dim_header)
        if (self.regex_trigger(payload)):
            return True
        # elif (...), aggiungere qui altre funzioni che possono determinare il drop
        #   return True
        return False

    # Funzione che estrae dal payload i dati su cui e' utile 
    # fare l'analisi. A determinare il tipo di estrazione e
    # raffinazione e' l'attributo service_type
    def digest(self, payload, dim_header=52):
        if (self.service_type == 'Raw'):        # Ovviamente questo e' solo per esempio, non ci sarà una if 
            payload = payload[dim_header:]      # per ogni servizio possibile, la variabile service_type
        return payload                          # sarà fatta in modo tale da permettere una classificazione generica
'''


        
