from django.utils.translation import gettext_lazy as _


# win-chrk4d7tc85 must be resolved in /etc/hosts or DNS
PROT_DOC_ENCODING = 'utf-8'
PROT_MAX_LABEL_LENGTH = 50
# most common oracle wildcard chars
PROT_UNALLOWED_CHARS = ['&', '(', ')', ',', '?', '!', '{', '}', '\\', '[', ']',
                        ':', '~', '|', '$', '<', '>', '*', '%',
                        ';', '"', "'"]

PROT_TEMPLATE_PATH = 'archipro_ws/xml_templates'
PROT_CREAZIONE_FASCICOLO_XML_PATH = '{}/generalizzati/creazione_fascicolo_standard.xml'.format(PROT_TEMPLATE_PATH)
PROT_TEMPLATE_FLUSSO_ENTRATA_DIPENDENTE_PATH='{}/unical/flusso_entrata.xml_standard.j2'.format(PROT_TEMPLATE_PATH)
PROT_ALLEGATO_EXAMPLE_FILE='{}/esempi/sample.pdf'.format(PROT_TEMPLATE_PATH)

# Flusso entrata per dipendenti
# mittente persona fisica come dipendente, destinatario Unical
PROT_PARAMETRI_TMPL_ROW = '<Parametro nome="{nome}" valore="{valore}" />'
PROT_PARAMETRI = [{'nome': 'agd', 'valore': '483'},
                  {'nome': 'uo', 'valore': '1231'}]

# DEFAULT EMAIL
PROT_EMAIL_DEFAULT = 'amministrazione@pec.unical.it'

# PROTOCOLLO, questi valori possono variare sulla base di come
# vengono istruite le pratiche all'interno del sistema di protocollo di riferimento
PROT_FASCICOLO_DEFAULT = '3'
PROT_TITOLARIO_DEFAULT = '9095'
# PROT_CODICI_TITOLARI = (
                           # ('9095','7.1'),
                           # ('9099', '7.5'),
                        # )

PROT_AOO = 'AOO55' # test

# TEST USE
PROT_URL = 'http://PROT_URL?wsdl'
PROT_LOGIN = 'UT_PROTO_WS55'
PROT_PASSW = 'UT_PROTO_WS55'

TITOLARIO_DICT = (
    ("9002", _("[9002] Normativa e relativa attuazione")),
    ("9003", _("[9003] Statuto")),
    ("9004", _("[9004] Regolamenti")),
    ("9005", _("[9005] Stemma, gonfalone e sigillo")),
    ("9006", _("[9006] Sistema informativo, sicurezza dell'informazione e sistema informatico")),
    ("9007", _("[9007] Protezione dei dati personali")),
    ("9008", _("[9008] Archivio")),
    ("9009", _("[9009] Trasparenza e relazioni con il pubblico")),
    ("9010", _("[9010] Strategie per il personale, organigramma e funzionigramma")),
    ("9011", _("[9011] Rapporti sindacali e contrattazione")),
    ("9012", _("[9012] Controllo di gestione e sistema qualità")),
    ("9013", _("[9013] Statistica e auditing")),
    ("9014", _("[9014] Elezioni e designazioni")),
    ("9015", _("[9015] Associazioni e attività culturali, sportive e ricreative")),
    ("9016", _("[9016] Editoria e attività informativo-promozionale")),
    ("9017", _("[9017] Onorificenze, cerimoniale e attività di rappresentanza")),
    ("9018", _("[9018] Politiche e interventi per le pari opportunità")),
    ("9019", _("[9019] Interventi di carattere politico, economico, sociale e umanitario")),
    ("9021", _("[9021] Rettore")),
    ("9022", _("[9022] Prorettore vicario e delegati")),
    ("9023", _("[9023] Direttore generale")),
    ("9024", _("[9024] Direttore")),
    ("9025", _("[9025] Presidente")),
    ("9026", _("[9026] Senato accademico")),
    ("9027", _("[9027] Consiglio di amministrazione")),
    ("9028", _("[9028] Consiglio")),
    ("9029", _("[9029] Giunta")),
    ("9030", _("[9030] Commissione didattica paritetica docenti-studenti")),
    ("9031", _("[9031] Nucleo di valutazione")),
    ("9032", _("[9032] Collegio dei revisori dei conti")),
    ("9033", _("[9033] Collegio di disciplina (per i docenti)")),
    ("9034", _("[9034] Senato degli studenti")),
    ("9035", _("[9035] Comitato unico di garanzia e per le pari opportunità")),
    ("9036", _("[9036] Comitato tecnico scientifico")),
    ("9037", _("[9037] Conferenza dei rettori delle università italiane] CRUI")),
    ("9038", _("[9038] Comitato regionale di coordinamento")),
    ("9039", _("[9039] Comitato per lo sport universitario")),
    ("9041", _("[9041] Ordinamento didattico")),
    ("9042", _("[9042] Corsi di studio")),
    ("9043", _("[9043] Corsi a ordinamento speciale")),
    ("9044", _("[9044] Corsi di specializzazione")),
    ("9045", _("[9045] Master")),
    ("9046", _("[9046] Corsi di dottorato")),
    ("9047", _("[9047] Corsi di perfezionamento e corsi di formazione permanente")),
    ("9048", _("[9048] Programmazione didattica, orario delle lezioni, gestione delle aule e degli spazi")),
    ("9049", _("[9049] Gestione di esami di profitto, di laurea e di prove di idoneità")),
    ("9050", _("[9050] Programmazione e sviluppo, comprese aree, macroaree e settori scientifico-disciplinari")),
    ("9051", _("[9051] Strategie e valutazione della didattica e della ricerca")),
    ("9052", _("[9052] Premi e borse di studio finalizzati e vincolati")),
    ("9053", _("[9053] Progetti e finanziamenti")),
    ("9054", _("[9054] Accordi per la didattica e la ricerca")),
    ("9055", _("[9055] Rapporti con enti e istituti di area socio-sanitaria")),
    ("9056", _("[9056] Opere dell'ingegno, brevetti e imprenditoria della ricerca")),
    ("9057", _("[9057] Piani di sviluppo dell'università")),
    ("9058", _("[9058] Cooperazione con paesi in via di sviluppo")),
    ("9059", _("[9059] Attività per conto terzi")),
    ("9061", _("[9061] Contenzioso")),
    ("9062", _("[9062] Atti di liberalità")),
    ("9063", _("[9063] Violazioni amministrative e reati")),
    ("9064", _("[9064] Responsabilità civile, penale e amministrativa del personale")),
    ("9065", _("[9065] Pareri e consulenze")),
    ("9067", _("[9067] Orientamento, informazione e tutorato")),
    ("9068", _("[9068] Selezioni, immatricolazioni e ammissioni")),
    ("9069", _("[9069] Trasferimenti e passaggi")),
    ("9070", _("[9070] Cursus studiorum e provvedimenti disciplinari")),
    ("9071", _("[9071] Diritto allo studio, assicurazioni, benefici economici, tasse e contributi")),
    ("9072", _("[9072] Tirocinio, formazione e attività di ricerca")),
    ("9073", _("[9073] Servizi di assistenza socio-sanitaria e a richiesta")),
    ("9074", _("[9074] Conclusione e cessazione della carriera di studio")),
    ("9075", _("[9075] Esami di stato e ordini professionali")),
    ("9076", _("[9076] Associazionismo, goliardia e manifestazioni organizzate da studenti o ex studenti")),
    ("9077", _("[9077] Benefici Legge 390/91 ")),
    ("9078", _("[9078] Servizi abitativi e mensa per gli studenti")),
    ("9079", _("[9079] Attività culturali e ricreative")),
    ("9081", _("[9081] Poli")),
    ("9082", _("[9082] Scuole e strutture di raccordo")),
    ("9083", _("[9083] Dipartimenti")),
    ("9084", _("[9084] Strutture a ordinamento speciale")),
    ("9085", _("[9085] Scuole di specializzazione")),
    ("9086", _("[9086] Scuole di dottorato")),
    ("9087", _("[9087] Scuole interdipartimentali")),
    ("9088", _("[9088] Centri")),
    ("9089", _("[9089] Sistema bibliotecario")),
    ("9090", _("[9090] Musei, pinacoteche e collezioni")),
    ("9091", _("[9091] Consorzi ed enti a partecipazione universitaria")),
    ("9092", _("[9092] Fondazioni")),
    ("9093", _("[9093] Servizi di ristorazione, alloggi e foresterie")),
    ("9095", _("[9095] Concorsi e selezioni")),
    ("9096", _("[9096] Assunzioni e cessazioni")),
    ("9097", _("[9097] Comandi e distacchi")),
    ("9098", _("[9098] Mansioni e incarichi")),
    ("9099", _("[9099] Carriera e inquadramenti")),
    ("9100", _("[9100] Retribuzione e compensi")),
    ("9101", _("[9101] Adempimenti fiscali, contributivi e assicurativi")),
    ("9102", _("[9102] Pre-ruolo, trattamento di quiescenza, buonuscita")),
    ("9103", _("[9103] Dichiarazioni di infermità ed equo indennizzo")),
    ("9104", _("[9104] Servizi a domanda individuale")),
    ("9105", _("[9105] Assenze")),
    ("9106", _("[9106] Tutela della salute e sorveglianza sanitaria")),
    ("9107", _("[9107] Valutazione, giudizi di merito e provvedimenti disciplinari")),
    ("9108", _("[9108] Formazione e aggiornamento professionale")),
    ("9109", _("[9109] Deontologia professionale ed etica del lavoro")),
    ("9110", _("[9110] Personale non strutturato")),
    ("9112", _("[9112] Ricavi ed entrate")),
    ("9113", _("[9113] Costi e uscite")),
    ("9114", _("[9114] Bilancio")),
    ("9115", _("[9115] Tesoreria, cassa e istituti di credito")),
    ("9116", _("[9116] Imposte, tasse, ritenute previdenziali e assistenziali")),
    ("9118", _("[9118] Progettazione e costruzione di opere edilizie con relativi impianti")),
    ("9119", _("[9119] Manutenzione ordinaria, straordinaria, ristrutturazione, restauro e destinazione d'uso")),
    ("9120", _("[9120] Sicurezza e messa a norma degli ambienti di lavoro")),
    ("9121", _("[9121] Telefonia e infrastruttura informatica")),
    ("9122", _("[9122] Programmazione Territoriale")),
    ("9124", _("[9124] Acquisizione e gestione di beni immobili e relativi servizi")),
    ("9125", _("[9125] Locazione di beni immobili, di beni mobili e relativi servizi")),
    ("9126", _("[9126] Alienazione di beni immobili e di beni mobili")),
    ("9127", _("[9127] Acquisizione e fornitura di beni mobili, di materiali e attrezzature non tecniche e di servizi")),
    ("9128", _("[9128] Manutenzione di beni mobili")),
    ("9129", _("[9129] Materiali, attrezzature, impiantistica e adempimenti tecnico-normativi")),
    ("9130", _("[9130] Partecipazioni e investimenti finanziari")),
    ("9131", _("[9131] Inventario, rendiconto patrimoniale, beni in comodato")),
    ("9132", _("[9132] Patrimonio culturale – Tutela e valorizzazione")),
    ("9133", _("[9133] Gestione dei rifiuti")),
    ("9134", _("[9134] Albo dei fornitori")),
    ("9135", _("[9135] Oggetti diversi")),
)
