Diese CLI soll die Arbeit mit   
    1) X.509 Zertifikaten
    2) DNS-Hostnamen 
vereinfachen 
 

Allgemeine Benutzung
  dns3cli [flags] [command] [args]

Vorhandene allgemeine Kommandos:
  version       Ausgabe der Programmversion
  help          Hilfe zu jedem Kommando 
  completion    Erzeugt ein  Autovervollständigungsskripts für die angegebene Shell 
                damit "tab" vervollstädigung funktioniert

Vorhandene Kommandos für DNS und Zertifikate
  dns           Einträge verwalten auf einen DNS-BACKEND
  cert          Zertifikate verwalten 
  login         temporärer Speicher für Passwörter und Token während einer Session 
                (zur Zeit nur für Linux unterstützt über "keyring" )

Allgemeine Optionen
  -c, --config string[="dns3lcli.yaml"]   Konfigurationdatei im  yaml-Format, ist eigentlich mehr oder weniger unverzichtbar
                                          Viele spezielle Parameter haben in einem spezifischen Projektumfeld fast immer 
                                          den selben Wert und sind dort abgelegt.
                                          D.h. innerhalb eines Projektumfeld wird eine von Spezialisten erstellte Konfigurationsdatei 
                                          verwendet und bei jedem Kommando mit übergeben.
  -v, --debug                             Mehr Information zum Ablauf des Kommandos um Fehler zu finden
  -f, --force                             Ermöglicht bei vielen Kommandos das überschreiben von Daten 
                                          z.B. einen vorhandenden DNS-Eintrag zu überschreiben
  -j, --json                              Das Ergebnis im JSON-Formatt statt Klartext ausgeben 

================================================================================================================

--Kommando Version
    Diese Komanndo gibt die Version von DNS3L-CLI aus
    host:~$ dns3lcli version

================================================================================================================

--Kommando Help
    Diese Kommand gibt einen Hilfstext aus
    host:~$ ./dns3lcli --help 
    host:~$ ./dns3lcli completion --help 

================================================================================================================

--Kommnado completion
    Bestandteil der Golib "corbra" github.com/spf13/cobra, siehe dort für die Details

================================================================================================================
   
--Kommando login
    Zur Zeit wird nur Linux unterstützt!
    Um Geheimnisse( Passwörter & Tokens) sicher in einem "Schlüsselbund" bzw. "Passworttresor" zu speichern
    wird unter Liunx der sogenannte KeyRing verwendet.
    Wird die Login-Session auf den jeweiligem System beendet, wird der Keyring gelöscht und mit ihm alle Daten
   
    -- Subkommandos     acme    Speicherung des Tokens für den Zugriff auf das Rest-API der ACME-Anwendung 
    -- Subkommandos     dns     Speicherung der Anmeldedaten des DNS-Backends 

    ------------------------------------------------------------------------------------------------------------
    
    ./dns3lcli login acme
        Speicher das Token für den Zugriff auf das ACME Rest API, 
        Diese Token erhält man durch einen speziellen Endpunkt, an dem man sich authentisiert

        typischer Aufruf für die Vorbereitung von weiteren Aufrufen zur Zertifikats-Verwaltung
            # Angabe der Konfigurationsdatei 
            # Benutzer aus der Konfigurations Datei unter acme.user verwenden 
            # Passwort wird zur Laufzeit von dns3lcli abgefragt
            # das Zugriffs-Token wird sicher gespeichert
            ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme

       
        Parameterbeschreibung
        --id                   Benutzer oder Account Name
                               Überschreibt alle anderen Optionen einen Benutzer anzugeben
                               andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_ACME_ID
                                    Konfigurationsdatei             acme.user 
 
        --secret                zugehörige Passwort zum Benutzer Account des AMCE-Providers
                                wird nur durch --terminal überschreibt
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_ACME_SECRET
                                    Konfigurationsdatei            acme.pass (meistens steht hier ein Dummy-Wert) 
                                    
        --terminal      Das Passwort wird von dns3lcli während der Ausführung abgefragt
                                Überschreibt alle anderen Möglichkeiten für die Password Eingabe

        --stdout        Das Token nicht im "Schlüsselbund/Passworttresor" speicher sondern auf der Konsol ausgeben 
                        Dies erfolgt als Klartext, kann mit --json auf JSON-Formatt umgestellt werden  

        --json          Das Token im JSON-Formatt ausgeben

    ------------------------------------------------------------------------------------------------------------

    ./dns3lcli login dns
        Speicher das Password für den Zugriff auf einen DNS Provider
        Zur Zeit werden von dns3lcli die folgende ProviderTypen unterstützt
            1) infoblox 
            2) geplant: otc 

        typischer Aufruf
            # Angabe der Konfigurationsdatei 
            # Benutzer aus der Konfigurations Datei unter dns.providers.infblxA.auth.user verwenden 
            # Passwort wird zur Laufzeit von dns3lcli abgefragt und sicher gespeichert 
            # und kann von dort für darauffolgende Aufrufe verwendet werden
            ./dns3lcli --config=dns3cli_config_example.yaml --terminal --backend="infblxA"  login dns

        Parameterbeschreibung

        --id=MyUserName         Benutzer oder Account Name für den DNS-Provider
                                Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_DNS_ID
                                    Konfigurationsdatei  
                                        Eintrag für infoblox unter  dns.providers.xxxxx.auth.user 
                                        Eintrag für otc unter       dns.providers.xxxxx.auth.ak  

        --secret=MyPassword     zugehörige Passwort zum Benutzer Account des DNS-Providers
                                Wird nur durch --terminal überschreibt
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_DNS_SECRET
                                    Konfigurationsdatei  
                                        Eintrag für infoblox unter  dns.providers.xxxxx.auth.pass 
                                        Eintrag für otc unter       dns.providers.xxxxx.auth.sk  

        --backend="infblxA"     Verweise auf einen Abschnitt unter dns.providers
                                In diesem Fall auf den Abschnitt dns.providers.infblxA
                                In diesem Abschnitt sind die für diesen Typ benötigten Daten abgelegt

        --stdout                bei "login dns" keine Funktion            
        --terminal              Das Passwort wird von dns3lcli während der Ausführung abgefragt
                                Überschreibt alle anderen Möglichkeiten für die Password Eingabe

================================================================================================================
   
--Kommando dns

    Zur Zeit unterstützte Subkommandos
        -- Subkommandos     add     neu anlegen und ändern eines DNS Eintrags
        -- Subkommandos     del     löschen eines DNS-Eintrags
    geplante Subkommandos
        -- Subkommandos     list    Gibt die unterstützen DNS Provider aus
        -- Subkommandos     query   

    Zur Zeit werden die folgenden DNS-Provider unterstützte
        Infoblox
    geplannt
        OTC

    ------------------------------------------------------------------------------------------------------------
    
    ./dns3lcli dns add
        Legt eine DNS Eintrag an bzw. ändert ihn. 
        Existierende Einträge werden nicht überschrieben, sonder der Vorgang wird abgebrochen
        Mit --force kann ein überschreiben erzwungen werden
        Zur Zeit werden folgende Typen unterstützt
            -- A-Record
        geplant sind 
            -- TXT
            -- CNAME

        typischer Aufruf
            # Angabe der Konfigurationsdatei 
            # Benutzer aus der Konfigurations Datei unter dns.providers.infblxA.auth.user verwenden 
            # Passwort wird zur Laufzeit von dns3lcli abgefragt und sicher gespeichert 
            # und kann von dort für darauffolgende Aufrufe verwendet werden
            ./dns3lcli --config=dns3cli_config_example.yaml --backend=infblxA --id=BetaTester --PWSafe  dns add test.sub.ibtest.foo.com  A 10.10.1.111 666

        Argumente
      	FQDN    Voll qualifizierter Domain Name 
  		TYPE    Resource record type, die folgende Werte sind erlaubt  A|TXT|CNAME 
                Der Wert bestimmt welche Werte unter DATA akzeptiert werden
  		DATA    IP-Address, String oder Canonical-Name entsprechend zum Wert von TYPE 
        SEC     Gültigkeit / Lebensdauer des Eintrags in Sekunden

        Parameterbeschreibung
        
        --backend="infblxA"     Verweise auf einen Abschnitt unter dns.providers
                                In diesem Fall auf den Abschnitt dns.providers.infblxA
                                In diesem Abschnitt sind die für diesen Typ benötigten Daten abgelegt
  		
        --force                 Wenn der Eintrag schon existiert wird dieser mit den neuen Daten überschrieben
		
        --id  		            Benutzer oder Account Name für den DNS-Provider
                                Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_DNS_ID
                                    Konfigurationsdatei  
                                        Eintrag für infoblox unter  dns.providers.xxxxx.auth.user 
                                        Eintrag für otc unter       dns.providers.xxxxx.auth.ak  
		
        --secret  	            zugehörige Passwort zum Benutzer Account des DNS-Providers
                                Wird nur durch --PWSafe überschreibt
                                Im Fall von --PWSafe kann --secret weggelassen werden
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_DNS_SECRET
                                    Konfigurationsdatei  
                                        Eintrag für infoblox unter  dns.providers.xxxxx.auth.pass 
                                        Eintrag für otc unter       dns.providers.xxxxx.auth.sk  
        
        --PWSafe                Überschreibt alle anderen Möglichkeiten für die Password Eingabe
                                Das Passwort wird von dns3lcli während der Ausführung aus dem "Schlüsselbund" bzw. "Passworttresor" entnommen 
                                Unter Liunx der sogenannte KeyRing verwendet. Das Password muss zuvor mit z.B.
                                ./dns3lcli --config=dns3cli_config_example.yaml --terminal --backend="XXXXXX"  login dns
                                in den Schlüsselbund eingefügt worden sein
                                Wird die Login-Session auf den jeweiligem System beendet, wird der Keyring gelöscht und mit ihm alle Daten
     ------------------------------------------------------------------------------------------------------------
    
    ./dns3lcli dns del

        löscht eine DNS Eintrag
        Zur Zeit werden folgende Typen unterstützt
            -- A-Record
        geplant sind 
            -- TXT
            -- CNAME
        
        typischer Aufruf
            # Angabe der Konfigurationsdatei 
            # Benutzer aus der Konfigurations Datei unter dns.providers.infblxA.auth.user verwenden 
            # Passwort wird zur Laufzeit von dns3lcli abgefragt und sicher gespeichert 
            # und kann von dort für darauffolgende Aufrufe verwendet werden
             ./dns3lcli --config=dns3cli_config_example.yaml --backend=infblxA --id=BetaTester --PWSafe dns del  test.sub.ibtest.foo.com  A 

        Argumente
      	FQDN    Voll qualifizierter Domain Name 
  		TYPE    Resource record type, die folgende Werte sind erlaubt  A|TXT|CNAME 
                Der Wert bestimmt welche Eintrag unter den FQDN gelöscht wird
  	
        Parameterbeschreibung
        
        --backend="infblxA"     Verweise auf einen Abschnitt unter dns.providers
                                In diesem Fall auf den Abschnitt dns.providers.infblxA
                                In diesem Abschnitt sind die für diesen Typ benötigten Daten abgelegt
 
        --id  		            Benutzer oder Account Name für den DNS-Provider
                                Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                Umgebungsvariable               $DNS3L_DNS_ID
                                    Konfigurationsdatei  
                                        Eintrag für infoblox unter  dns.providers.xxxxx.auth.user 
                                        Eintrag für otc unter       dns.providers.xxxxx.auth.ak  
		
        --secret  	            zugehörige Passwort zum Benutzer Account des DNS-Providers
                                Wird nur durch --PWSafe überschreibt
                                Im Fall von --PWSafe kann --secret weggelassen werden
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_DNS_SECRET
                                    Konfigurationsdatei  
                                        Eintrag für infoblox unter  dns.providers.xxxxx.auth.pass 
                                        Eintrag für otc unter       dns.providers.xxxxx.auth.sk  
        
        --PWSafe                Überschreibt alle anderen Möglichkeiten für die Password Eingabe
                                Das Passwort wird von dns3lcli während der Ausführung aus dem "Schlüsselbund" bzw. "Passworttresor" entnommen 
                                Unter Liunx wird der sogenannte KeyRing verwendet. Das Password muss zuvor mit z.B.
                                ./dns3lcli --config=dns3cli_config_example.yaml --terminal --backend="XXXXXX"  login dns
                                in den Schlüsselbund eingefügt worden sein
                                Wird die Login-Session auf den jeweiligem System beendet, wird der Keyring gelöscht und mit ihm alle Daten

================================================================================================================
--Kommando cert

    Zur Zeit unterstützte Subkommandos
        -- Subkommandos     ca      Alle unterstützte Zertifizierungsstellen ausgeben
        -- Subkommandos     list    Alle Zertifikate der "dns3l" Instanz ausgeben
        -- Subkommandos     claim   Übertragen einer CSR (Zertifikat-Anfrage)
        -- Subkommandos     get     Ein Zertifikat von "dns3l" herunterladen
        -- Subkommandos     del     Löschen eines Zertifikats

    geplante Subkommandos   für none ACME CAs
        -- Subkommandos     csr     Anlegen eines CSR (Zertifikat-Anfrage) und 
                                    privaten Schlüssel "private key" PK auf DNS3L für CAs die kein ACME unterstützen
        -- Subkommandos     push    Übertragen eines Zertifikats nach DNS3L für CAs die kein ACME unterstützen

-----------------------------------------------------------------------------------------
./dns3lcli cert ca

    typischer Aufruf
    Wichtig zuvor wurde das Access-Token im Schlüsselbund bzw. ENV gespeichert
    Z.B. mit ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme

        # Angabe der Konfigurationsdatei 
        # Ausgabe im JSON-Formatt
        # API Endpunkt Benutzer .. wird aus der Konfigurations Datei entnommen
        # AccessToken aus dem KeyRing bzw. ENV
        ./dns3lcli --config=dns3cli_config_example.yaml json=true  cert ca  

    Argumente
        keine

    Parameterbeschreibung
        --api           ACME Backend API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                        andere Optionen in absteigender Priorität
                                Umgebungsvariable               $DNS3L_CERT_API
                                Konfigurationsdatei Wert aus    cert.api
    	--json          Die Liste im JSON-Formatt ausgeben
	    --tok           Das Access-Token für ACME API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                        andere Optionen in absteigender Priorität
                                Umgebungsvariable               $DNS3L_CERT_API
                                Konfigurationsdatei Wert aus    cert.accessToken
                                Wenn vorhanden Wert aus KeyRing  

-----------------------------------------------------------------------------------------
./dns3lcli cert list
    Gib alle Zertifikate aus, welche zu einer CA gehören, die von dns3l angesprochen werden kann
    und vom Filter(--search) durchgelassen werden

    typischer Aufruf
        # Wichtig zuvor wurde das Access-Token im Schlüsselbund bzw. ENV gespeichert
        # Z.B. mit ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # Angabe der Konfigurationsdatei 
        # Ausgabe im JSON-Formatt
        # API Endpunkt Benutzer .. wird aus der Konfigurations Datei entnommen
        # AccessToken aus dem KeyRing bzw. ENV
        # --ca=MyCertAuth wähle die CA aus die DNS3L-ACME  verwenden soll
        # --search regulärer Ausdruck
        ./dns3lcli --config=dns3cli_config_example.yaml json=true   cert list --ca=MyCertAuth  
        ./dns3lcli --config=dns3cli_config_example.yaml json=true   cert list --ca=MyCertAuth --search=[^\s\S]*.otc.de
        ./dns3lcli --config=dns3cli_config_example.yaml json=true   cert list --ca=MyCertAuth --search=.*.cloud.de

    Argumente
        keine

    Parameterbeschreibung
        --api           ACME Backend API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                        andere Optionen in absteigender Priorität
                            Umgebungsvariable               $DNS3L_CERT_API
                            Konfigurationsdatei Wert aus    cert.api
    	--json          Die Liste im JSON-Formatt ausgeben
	    --tok           Das Access-Token für ACME API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                        andere Optionen in absteigender Priorität
                            Umgebungsvariable               $DNS3L_CERT_API
                            Konfigurationsdatei Wert aus    cert.accessToken
                            Wenn vorhanden Wert aus KeyRing  
        --ca            CA die verwendet werden soll
        --filter        regulärer re2 Ausdruck
                        Die Syntax entspricht weitgehed der vom Perl, Python
                        https://github.com/google/re2/wiki/Syntax

    -----------------------------------------------------------------------------------------
    ./dns3lcli cert claim
        Erstellt eine Zertifikat, 
        welches man dann später mit cert get herunterlädt

        typischer Aufruf
        # Wichtig zuvor wurde das Access-Token im Schlüsselbund bzw. ENV gespeichert
        # Z.B. mit ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # Angabe der Konfigurationsdatei 
        # Ausgabe im JSON-Formatt
        # API Endpunkt Benutzer .. wird aus der Konfigurations Datei entnommen
        # Hints werden aus dem Defaults-Abschnitt für Hints entnommen (cert.hints.default)
        # AccessToken aus dem KeyRing bzw. ENV
        # --ca=MyCertAuth wähle die CA aus die DNS3L-ACME  verwenden soll
        # --autodns=10.1.2.3   IP Adressse für FQDN
        # FQDN test.test.cloud.de
        # SAN  jira.test.cloud.de
        ./dns3lcli --config=dns3cli_config_example.yaml json=true  \..
                cert claim --ca=MyCertAuth  --autodns=10.1.2.3  test.test.cloud.de   jira.test.cloud.de 
 
    Argumente FQDN [SAN [SAN [...]]]
        FQDN            Voll qualifizierter Domain Name
        SAN             Subject Alternative Name

    Parameterbeschreibung
    	--json          Die Liste im JSON-Formatt ausgeben
	    --tok           Das Access-Token für ACME API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_CERT_API
                                    Konfigurationsdatei Wert aus    cert.accessToken
                                    Wenn vorhanden Wert aus KeyRing  
        --api           ACME Backend API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_CERT_API
                                    Konfigurationsdatei Wert aus    cert.api
        --ca            CA die verwendet werden soll
        --wildcard      erzeugt ein Wildcard Zertifikate kann nicht mit --autodns verwendet werden 
  		--autodns       erzeugt aus der angegebene IP eine DNS A-Record, kann nicht mit wildcard verwedet werden
        --hints         string[="default"] "hints"-Abschnitt in der Konfigurationsdatei, welche verwendet werden soll
                        Standardwert ist cert.hints.default 

-----------------------------------------------------------------------------------------
./dns3lcli cert get

    lädt ein Zertifikat herunter

    typischer Aufruf
    # Wichtig zuvor wurde das Access-Token im Schlüsselbund bzw. ENV gespeichert
    # Z.B. mit ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
    # Angabe der Konfigurationsdatei 
    # Ausgabe im JSON-Formatt
    # API Endpunkt Benutzer .. wird aus der Konfigurations Datei entnommen
    # AccessToken aus dem KeyRing bzw. ENV
    # --ca=MyCertAuth  CA auf der das Zertifikat erzeugt wurde
    # --mode=full das Zertifikat und die dazugehörige chain wird heruntergeladen 
    # arg FQDN test.test.cloud.de
    ./dns3lcli --config=dns3cli_config_example.yaml json=true  --ca=MyCertAuth -mode=full  cert get  test.test.cloud.de
        
    Argumente
        FQDN            Voll qualifizierter Domain Name

    Parameterbeschreibung
        --api           ACME Backend API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_CERT_API
                                    Konfigurationsdatei Wert aus    cert.api
    	--json          Die Liste im JSON-Formatt ausgeben
	    --tok           Das Access-Token für ACME API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_CERT_API
                                    Konfigurationsdatei Wert aus    cert.accessToken
                                    Wenn vorhanden Wert aus KeyRing  
        --ca            CA die verwendet werden soll
        --mode          Was genau alles zu diesem FQDN herunter geladen wird
                        full        = Zertifikat plus Zertifikatskette (default)
                        cert        = Zertifikat  
                        chain       = Zertifikatskette
                        root        = Root-Zertifikat
                        privatekey  = Private Schlüssel zum Zertifikat

 -----------------------------------------------------------------------------------------

./dns3lcli cert del

        Löscht eine Zertifikat

        typischer Aufruf
        # Wichtig zuvor wurde das Access-Token im Schlüsselbund bzw. ENV gespeichert
        # Z.B. mit ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # --config=dns3cli_config_example.yaml Angabe der Konfigurationsdatei 
        # API Endpunkt wird aus der Konfigurations Datei entnommen
        # AccessToken aus dem KeyRing bzw. ENV
        # --ca=MyCertAuth wähle die CA aus, die DNS3L-ACME  verwenden soll
        # arg FQDN  test.test.cloud.de

        ./dns3lcli --config=dns3cli_config_example.yaml --ca=MyCertAuth cert del  test.test.cloud.de  

    Argumente
        FQDN            Voll qualifizierter Domain Name

    Parameterbeschreibung relevant für diese Kommand, welche über -c, -v, ... hinaugehen
        --json          Die Liste im JSON-Formatt ausgeben
	    --tok           Das Access-Token für ACME API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_CERT_API
                                    Konfigurationsdatei Wert aus    cert.accessToken
                                    Wenn vorhanden Wert aus KeyRing  
        --api           ACME Backend API Endpunkt 
                        Überschreibt alle anderen Optionen einen Benutzer anzugeben
                                andere Optionen in absteigender Priorität
                                    Umgebungsvariable               $DNS3L_CERT_API
                                    Konfigurationsdatei Wert aus    cert.api
        --ca            CA die verwendet werden soll
                
-----------------------------------------------------------------------------------------
