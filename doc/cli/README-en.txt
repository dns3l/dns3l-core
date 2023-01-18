This CLI is designed to simplify work with
1) X. 509 Certificates
2) DNS hostname



General use
dns3cli [flags] [command] [args]

Existing general commands:
    version     output of the program version
    help        help for each command
    completion  creates an autocomplete script for the specified shell
                so that "tab" completion works

Existing commands for DNS and certificates
    dns     manage entries on a DNS BACKEND
    cert    manage certificates
    login   temporary memory for passwords and tokens during a session 
            (currently only supported for Linux via "keyring")

General options
    -c, --config string[="dns3lcli.yaml"]  configuration file in the yaml format, 
                                            is actually more or less indispensable
                                            Many special parameters in a specific project 
                                            environment almost always have the same value 
                                            and are stored there. i. e. within a project 
                                            environment a configuration file created 
                                            by specialists used  passed with each command.
    -v, --debug                             More information about how to run the command 
                                            to find errors
    -f, --force                             Allows data overwriting for many commands
                                            e. g. overwrite an existing DNS entry
    -j, --json                              Output the result in JSON format instead of plain text

================================================================================================================

--command Version
    This command will output the version of DNS3L-CLI
    host:~$ dns3lcli version

================================================================================================================
--command Help
    This command prints a help text
    host:~$ . /dns3lcli --help
    host:~$ . /dns3lcli completion --help

================================================================================================================
--commnado completion
    Part of the Golib "corbra" github.com/spf13/cobra, see there for details

================================================================================================================

--comando login
    Currently only Linux is supported!
    To store secrets (passwords & tokens) securely in a "key ring" or "password vault"
    the so-called KeyRing is used under Liunx.
    If the login session on the respective system is terminated, the keyring is deleted 
    and all data with it

    -- subcommands acme Store the token for accessing the rest API of the ACME application
    -- subcommands dns Storage of the login data of the DNS backend

------------------------------------------------------------------------------------------------------------

. /dns3lcli login acme
    Save the token for accessing the ACME Rest API,
    These tokens are obtained through a special endpoint, where you authenticate

    typical call for the preparation of further calls to the certificate management
        # Specify the configuration file
        # Use users from the configuration file at acme. user
        # Password is queried at runtime by dns3lcli
        # the access token is stored securely
        . /dns3lcli --config=dns3cli_config_example.yaml --terminal login acme


    parameter description
    --id                    user or account Name
                            overrides all other options to specify a user
                            other options in descending priority
                                Environment variable    $DNS3L_ACME_ID
                                Configuration File      acme.user

    --secret                password associated with the user account of the AMCE provider
                            is only overwritten by --terminal
                            other options in descending priority
                                Environment variable    $DNS3L_ACME_SECRET
                                Configuration file      acme.pass (usually there is a dummy value here)

    --terminal              The password is queried by dns3lcli during execution
                            overrides all other options for password entry

    --stdout                do not store the token in the "keychain/password vault" but output it on the console
                            this is done as plain text, can be converted to JSON format with --json

    --json                  output the token in JSON format

    ------------------------------------------------------------------------------------------------------------
    
    ./dns3lcli login dns
        Save the password to access a DNS provider
    Currently the following provider types are supported by dns3lcli
        1) infoblox
        2) planned: otc

    typical call
        # Specify the configuration file
        # Use users from the configuration file at dns. providers. infblxA. auth. user
        # Password is queried at runtime by dns3lcli and stored securely
        # and can be used from there for subsequent calls
        ./dns3lcli --config=dns3cli_config_example.yaml --terminal --backend="infblxA" login dns

    parameter description

    --id=MyUserName         user or account name for the DNS provider
                            overrides all other options to specify a user
                            other options in descending priority
                                environment variable        $DNS3L_DNS_ID
                                configuration file
                                    entry for infoblox at   dns.providers. xxxxx. auth. user
                                    entry for otc at        dns.providers. xxxxx. auth. ak

    --secret=MyPassword     password associated with the user account of the DNS provider
                            Overridden only by --terminal
                                other options in descending priority
                                environment variable $DNS3L_DNS_SECRET
                                configuration file
                                    entry for infoblox at   dns.providers. xxxxx. auth. pass
                                    entry for otc at        dns.providers. xxxxx. auth. sk

    --backend="infblxA"         references to a section under dns. providers
                                In this case, the section dns.providers.infblxA
                                This section contains the data required for this type

    --stdout                    with login dns no function
    --terminal                  the password is queried by dns3lcli during execution
                                overrides all other options for password entry
 
================================================================================================================

--command dns

    Currently supported subcommands
        -- subcommands add      create and modify subcommands add
        -- subcommands delete   delete a DNS entry
    planned subcommands
        -- subcommands list Outputs the supported DNS providers
        -- subcommands query

    Currently the following DNS providers are supported
        Infoblox
    planned
        OTC

    ------------------------------------------------------------------------------------------------------------
    
    ./dns3lcli dns add
        Creates or modifies a DNS entry.
        Existing entries are not overwritten, but the process is aborted
        Use --force to force an override
        Currently the following types are supported
            -- A-Record
        are planned
            -- TXT
            -- CNAME

        typical call
            # Specify the configuration file
            # Use users from the configuration file at dns.providers.infblxA.auth.user
            # Password is queried at runtime by dns3lcli and stored securely
            # and can be used from there for subsequent calls
            ./dns3lcli --config=dns3cli_config_example.yaml --backend=infblxA --id=BetaTester --PWSafe dns add test.sub.ibtest.foo.com A 10.10.1.111 666
        
        arguments
            FQDN    Fully Qualified Domain Name
            TYPE    Resource record type, the following values are allowed A|TXT|CNAME
                    The value determines which values are accepted under DATA
            DATA    IP address, string or Canonical name corresponding to the value of TYPE
            SEC     validity / lifetime of the entry in seconds

        parameter description

        --backend="infblxA"     references to a section under dns. providers
                                in this case, the section dns.providers.infblxA
                                this section contains the data required for this type

        --force                 if the entry already exists, it will be overwritten with the new data

        --id                    user or account name for the DNS provider
                                overrides all other options to specify a user
                                other options in descending priority
                                    environment variable    $DNS3L_DNS_ID
                                    configuration File
                                        entry for infoblox at   dns.providers.xxxxx.auth.user
                                        entry for otc at        dns.providers.xxxxx.auth.ak

        --secret                password associated with the user account of the DNS provider
                                overridden only by --PWSafe
                                in the case of --PWSafe --secret can be omitted
                                other options in descending priority
                                    environment variable $DNS3L_DNS_SECRET
                                configuration File
                                        entry for infoblox at dns. providers.xxxxx.auth.pass
                                        entry for otc at dns. providers.xxxxx.auth.sk

        --PWSafe                overrides all other options for password entry
                                the password is taken by dns3lcli during execution from the 
                                "key ring" or "password vault"
                                under Liunx the so-called KeyRing is used. 
                                The password must have been inserted into the keychain with a cmd like this
                                . /dns3lcli --config=dns3cli_config_example.yaml --terminal --backend="XXXXXX" login dns
                                if the login session on the respective system is terminated, 
                                the keyring is deleted and all data with it 
     ------------------------------------------------------------------------------------------------------------

    ./dns3lcli dns del
        deletes a DNS entry
        Currently the following types are supported
            -- A-Record
        are planned
            -- TXT
            -- CNAME

        typical call
        # Specify the configuration file
        # Use users from the configuration file at dns. providers. infblxA. auth. user
        # Password is queried at runtime by dns3lcli and stored securely
        # and can be used from there for subsequent calls
        ./dns3lcli --config=dns3cli_config_example.yaml --backend=infblxA --id=BetaTester --PWSafe dns del test.sub.ibtest.foo.com

        arguments
        FQDN    Fully Qualified Domain Name
        TYPE    Resource record type, the following values are allowed A|TXT|CNAME
                The value determines which entry is deleted under the FQDN

        parameter description

        --backend="infblxA"     references to a section under dns. providers
                                in this case, the section dns. providers.infblxA
                                this section contains the data required for this type

        --id                    user or account name for the DNS provider
                                overrides all other options to specify a user
                                other options in descending priority
                                    environment variable    $DNS3L_DNS_ID
                                    configuration File
                                            entry for infoblox at   dns.providers.xxxxx.auth.user
                                            entry for otc at        dns.providers.xxxxx.auth.ak

        --secret                password associated with the user account of the DNS provider
                                overridden only by --PWSafe
                                in the case of --PWSafe --secret can be omitted
                                other options in descending priority
                                    environment variable    $DNS3L_DNS_SECRET
                                    configuration File
                                        entry for infoblox at   dns.providers.xxxxx.auth.pass
                                        entry for otc at        dns.providers.xxxxx.auth.sk

-       -PWSafe                 overrides all other options for password entry
                                the password is taken by dns3lcli during execution from 
                                the "key ring" or "password vault"
                                under Liunx, the so-called KeyRing is used. The password must 
                                have been inserted into the keychain with a cmd like this
                                ./dns3lcli --config=dns3cli_config_example.yaml --terminal --backend="XXXXXX" login dns
                                if the login session on the respective system is terminated, 
                                the keyring is deleted and all data with it

    ================================================================================================================
    --command cert

    currently supported subcommands
        -- subcommands ca       output all supported CAs
        -- subcommands list     print all certificates of the "dns3l" instance
        -- subcommands claim    transfer a certificate request to acme
        -- subcommands get      download a certificate from "dns3l"
        -- subcommands del      deleting a Certificate on acme

    scheduled subcommands for none ACME CAs
        -- Subcommands csr      create a CSR (certificate request) and
                                private key "private key" PK on DNS3L for CAs that do not support ACME
        -- Subcommands push     transfer a certificate to DNS3L for CAs that do not support ACME

-----------------------------------------------------------------------------------------
   ./dns3lcli cert ca

    typical call
    Important before, the Access token was stored in the keychain or ENV
    E. g. with ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme

        # Specify the configuration file
        # Output in JSON format
        # API endpoint user .. is taken from the configuration file
        # AccessToken from the KeyRing or ENV
        ./dns3lcli --config=dns3cli_config_example.yaml json=true cert ca

    Arguments
        none

    parameter description
        --api               ACME backend API endpoint
                            overrides all other options to specify a user
                            other options in descending priority
                                environment variable            $DNS3L_CERT_API
                                configuration File Value from   cert.api
        --json                Print the list in JSON format
        --tok           The access token for ACME API endpoint
                        Overrides all other options to specify a user
                        other options in descending priority
                            Environment variable            $DNS3L_CERT_API
                            Configuration File Value from   cert.accessToken
                            If present value from           KeyRing

-----------------------------------------------------------------------------------------
. /dns3lcli cert list
    Issue all certificates belonging to a CA that can be accessed by dns3l
    and passed by the filter(--search)

    typical call
        # Important Before, the Access token was stored in the keychain or ENV
        # E. g. with ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # Specify the configuration file
        # Output in JSON format
        # API endpoint user . . is taken from the configuration file
        # AccessToken from the KeyRing or ENV
        # --ca=MyCertAuth select the CA to use DNS3L-ACME
        # --search regular expression
        ./dns3lcli --config=dns3cli_config_example.yaml json=true cert list --ca=MyCertAuth
        ./dns3lcli --config=dns3cli_config_example.yaml json=true cert list --ca=MyCertAuth --search=[^\s\S]*. otc. de
        ./dns3lcli --config=dns3cli_config_example.yaml json=true cert list --ca=MyCertAuth --search=. *. cloud. de

    Arguments
        none

        Parameter description
            --api               ACME backend API endpoint
                                overrides all other options to specify a user
                                other options in descending priority
                                    Environment variable            $DNS3L_CERT_API
                                    Configuration File Value from   cert.api
            --json              print the list in JSON format
            --tok               the access token for ACME API endpoint
                                overrides all other options to specify a user
                                other options in descending priority
                                    Environment variable            $DNS3L_CERT_API
                                    Configuration File Value from   cert.accessToken
                                    If present value from KeyRing
            --ca                CA to use
            --filter            regular re2 expression
                                The syntax is broadly equivalent to that of Perl, Python
                                https://github. com/google/re2/wiki/Syntax

    -----------------------------------------------------------------------------------------
    ./dns3lcli cert claim
        Creates a certificate,
        which you then download later with cert get

        typical call
        # Important Before, the Access token was stored in the keychain or ENV
        # E. g. with ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # Specify the configuration file
        # Output in JSON format
        # API endpoint user . . is taken from the configuration file
        # Hints are taken from the defaults section for hints (cert. hints. default)
        # AccessToken from the KeyRing or ENV
        # --ca=MyCertAuth select the CA to use DNS3L-ACME
        # --autodns=10.1.2.3 IP address for FQDN
        # FQDN test.test.cloud.de
        # SAN jira.test.cloud.de
        ./dns3lcli --config=dns3cli_config_example. yaml json=true \..
                cert claim --ca=MyCertAuth --autodns=10.1.2.3 test.test.cloud.de jira.test.cloud.de

        Arguments FQDN [SAN [SAN [. . . ]]]
            FQDN    Fully qualified domain name
            SAN     Subject Alternative name

        Parameter description
            --json              print the list in JSON format
            --tok               the access token for ACME API endpoint
                                overrides all other options to specify a user
                                other options in descending priority
                                    Environment variable $DNS3L_CERT_API
                                    Configuration File Value from cert.accessToken
                                    If present value from KeyRing
            --api               ACME backend API endpoint
                                overrides all other options to specify a user
                                other options in descending priority
                                environment variable $DNS3L_CERT_API
                                configuration File Value from cert. api
            --ca                CA to use
            --wildcard          creates a wildcard certificate cannot be used with --autodns
            --autodns           creates a DNS A record from the specified IP, cannot be used with wildcard
            --hints             string[="default"] "hints" section in the configuration file to be used
                                Default value is cert. hints. default
    -----------------------------------------------------------------------------------------
    /dns3lcli cert get

        loads a certificate

        typical call
        # Important Before, the Access token was stored in the keychain or ENV
        # E. g. with ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # Specify the configuration file
        # Output in JSON format
        # API endpoint user . . is taken from the configuration file
        # AccessToken from the KeyRing or ENV
        # --ca=MyCertAuth CA on which the certificate was created
        # --mode=full the certificate and the corresponding chain is downloaded
        # arg FQDN test.test.cloud.de
        . /dns3lcli --config=dns3cli_config_example.yaml json=true --ca=MyCertAuth -mode=full cert get test.test.cloud.de

        Arguments
            FQDN Fully qualified domain name

        Parameter description
            --api               ACME backend API endpoint
                                Overrides all other options to specify a user
                                other options in descending priority
                                    Environment variable            $DNS3L_CERT_API
                                    Configuration File Value from   cert.api
            --json              Print the list in JSON format
            --tok               The access token for ACME API endpoint
                                Overrides all other options to specify a user
                                other options in descending priority
                                Environment variable                $DNS3L_CERT_API
                                Configuration File Value from       cert.accessToken
                                If present value from KeyRing
            --ca                CA to use
            --mode              What exactly is downloaded for this FQDN
                                    full = certificate plus certificate chain (default)
                                    cert = certificate
                                    chain = certificate chain
                                    root = root certificate
                                    privatekey = private key to the certificate

    -----------------------------------------------------------------------------------------

    ./dns3lcli cert del

        Deletes a certificate

        typical call
        # Important Before, the Access token was stored in the keychain or ENV
        # E. g. with ./dns3lcli --config=dns3cli_config_example.yaml --terminal login acme
        # --config=dns3cli_config_example.yaml Specify the configuration file
        # API endpoint is taken from the configuration file
        # AccessToken from the KeyRing or ENV
        # --ca=MyCertAuth select the CA to use DNS3L-ACME
        # arg FQDN test.test.cloud.de

        ./dns3lcli --config=dns3cli_config_example.yaml --ca=MyCertAuth cert del test.test.cloud.de

        arguments
            FQDN Fully qualified domain name

        parameter description relevant to this command, which goes beyond -c, -v, ...
            --json          Print the list in JSON format
            --tok           The access token for ACME API endpoint
                            overrides all other options to specify a user
                            other options in descending priority
                                environment variable            $DNS3L_CERT_API
                                onfiguration File Value from    cert.accessToken
                                If present value from KeyRing
            --api           ACME backend API endpoint
                            Overrides all other options to specify a user
                            other options in descending priority
                                environment variable            $DNS3L_CERT_API
                                configuration File Value from   cert.api
            --ca            CA to use

-----------------------------------------------------------------------------------------
