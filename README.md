# Single Sign On Kerberos
## Pré requis
* Compte système + mot de passe
* Service Principal Name (SPN) lié au compte de service
* Fichier `keytab` associé 

Le fichier `keytab` doit être créé pour tous les algorithmes de cryptage
```bash
# Exemple de ligne de commande pour creér le fichier keytab
##    Nom du principal      : HTTP/ged.cpam-marseille.cnamts.fr@CNAMTS.LOCAL
##    Nom du compte système : C111301-ALFRESCO-P@cnamts.local
##    Nom du fichier keytab : KT-111301-L111301HAALF.keytab

ktpass -princ HTTP/ged.cpam-marseille.cnamts.fr@CNAMTS.LOCAL 
       -mapuser C111301-ALFRESCO-P@cnamts.local 
       -pass * 
       -crypto all 
       -ptype KRB5_NT_PRINCIPAL 
       -out KT-111301-L111301HAALF.keytab
```

Le compte système et le mot de passe associé peuvent être créés par la Caisse.
Par contre, le principal (SPN), les délégations associées au compte et le fichier 
`keytab` doivent être fournis par le national. Une demande CSN est nécessaire.

Les éléments variables et repris dans les fichiers de configuration de cette procédure sont:
* varSpn : nom du principal (ex : HTTP/ged.cpam-marseille.cnamts.fr@CNAMTS.LOCAL).
* varCompte_AD : nom du compte de l'active directory (ex : C111301-ALFRESCO-P@cnamts.local).
* varPwd_AD : mot de passe du compte de l'AD.
* varKeytab : nom et chemin du fichier keytab généré par le national (ex : /opt/kerberos/KT-111301-L111301REVERS-Q.keytab).
* varDomaine_Url : domaine des url d'accès à la plateforme (ex : cnamts.fr).
* varIpAlfresco : adresse Ip du serveur ALFRESCO.


## NOTE

Les fichiers ".keytab" sont dans le répertoire /SSO Kerberos/keytabs. 
Ils ont un format spécifique. (Taille d'un fichier: -1 Ko).

Il est préférable de les télécharger en cliquant dessus puis sur le bouton "Download".

`Ne pas faire un "clique droit" sur le fichier, puis "enregistrer sous..."`, Le format du fichier pourrait se transformer en format Txt, et ne plus être exploitable.


## ASTUCE

Pour vérifier que le format d'un fichier .keytab est correct, exécuter en ligne de commande:
```bash
yum list krb5*
```
Vous devriez trouver dans la liste: krb5-workstation.x86_64, exécuter:
```bash
yum install krb5-workstation.x86_64
```
Une fois le message "Installation terminée !", exécuter:
```bash
kinit -V -k -t /opt/KT111301-L111301xxxxxx.keytab HTTP/yyyyy.cpam-marseille.cnamts.fr@CNAMTS.LOCAL
```
xxxxx = le fichier KEYTAB concerné:
```bash
KT-111301-L111301HAALF.keytab        # pour l'instance de production
KT-111301-L111301REVERS-DEV.keytab   # pour l'instance de développement
KT-111301-L111301REVERS-Q.keytab     # pour l'instance de qualification.
```

yyyyyy = instance concernée:
```bash
HTTP/ged.cpam-marseille.cnamts.fr@CNAMTS.LOCAL       # pour l'instance de production
HTTP/ged-d.cpam-marseille.cnamts.fr@CNAMTS.LOCAL     # pour l'instance de développement
HTTP/ged-q.cpam-marseille.cnamts.fr@CNAMTS.LOCAL     # pour l'instance de qualification
```

Si le message "Pre-authenfication failed: `Unsupported key table format version version` while getting initial credentials", apparait, cela signifie que le format n'est peut-être pas correct.

Dans ce cas, déposer dans le répertoire (voir plus bas) le "bon" fichier KEYTAB. Puis relancer Tomcat:
```bash
systemctl restart tomcat
```



## Paramétres des navigateurs
### Internet Explorer
* Ajouter le domaine principal dans les sites de confiance du navigateur.
* Une GPO présente sur nos postes de travail ajoutent le domaine `cnamts.fr` est déjà créée.
* Aucune modification n'est donc nécessaire pour `Internet Explorer`.

### Firefox
* Modification des paramétres à l'aide des outils de configuration `about:config`.

```bash
network.negotiate-auth.delegation-uris=varDomaine_Url
network.negotiate-auth.trusted-uris=varDomaine_Url
```

* Ces modifications peuvent être faites en centralisées à partir d'une GPO pour 
modifier le fichier de configuration de Firefox sur les postes de travail :
`C:\Program Files (x86)\Mozilla Firefox\Firefox.cfg`

## Paramétres des clients
* Pour permettre l'utilisation des protocoles `WebDav` et `AOS` directement à partir
d'un explorateur Windows, il est nécessaire de modifier des clés de registre.

```bash
HKEY_CURRENT_USER\Software\Microsoft\OFFICE\14.0\Common\Internet 
BasicAuthLevel (REG_DWORD) = 0x2 (2)

HKEY_LOCAL_MACHINE\System\CurrentControlSet\service\WebClient\Parameters 
BasicAuthLevel (REG_DWORD) = 0x2 (2)
```

* Ces clés de registre sont modifiées dans le système à partir d'une GPO locale dans 
notre environnement.

## Paramétrages du serveur `ALFRESCO`

### Paramétrages JAVA pour Kerberos

#### Modification du fichier `java.login.config`
* Editer ou créer le fichier `java.login.config`
 
```bash
vim /usr/lib/jvm/java-1.8.0/jre/lib/security/java.login.config
```

* Ajouter le paramétrage suivant

```bash
Alfresco {
   com.sun.security.auth.module.Krb5LoginModule sufficient;
};

AlfrescoHTTP
{
   com.sun.security.auth.module.Krb5LoginModule required
   storeKey=true
   useKeyTab=true
   doNotPrompt=true
   keyTab="varKeyTab"
   principal="varSpn";
};

com.sun.net.ssl.client {
   com.sun.security.auth.module.Krb5LoginModule sufficient;
};

other {
   com.sun.security.auth.module.Krb5LoginModule sufficient;
};
```

* Les variables `keytab` et `principal` doivent avoir une valeur en fonction du nom du SPN et du fichier keytab fourni.

* `/!\ Rappel` varKeytab = nom et chemin du fichier keytab généré par le national. Ce dernier met à disposition 3 fichiers .keytab:

```bash
KT-111301-L111301HAALF.keytab        # pour l'instance de production
KT-111301-L111301REVERS-DEV.keytab   # pour l'instance de développement
KT-111301-L111301REVERS-Q.keytab     # pour l'instance de qualification.
```
Exemple: pour le développement,  keyTab="/opt/kerberos/KT-111301-L111301REVERS-DEV.keytab"

* Pour varSpn = nom du principal. Il en existe 3:

```bash
HTTP/ged.cpam-marseille.cnamts.fr@CNAMTS.LOCAL       # pour l'instance de production
HTTP/ged-d.cpam-marseille.cnamts.fr@CNAMTS.LOCAL     # pour l'instance de développement
HTTP/ged-q.cpam-marseille.cnamts.fr@CNAMTS.LOCAL     # pour l'instance de qualification
```
Exemple: pour le développement,  varSpn="HTTP/ged-d.cpam-marseille.cnamts.fr@CNAMTS.LOCAL"


#### Modification du fichier `java.security`
* Editer le fichier `java.security`

```bash
vim /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-7.b13.el7.x86_64/jre/lib/security/java.security
```

* Modifier la variable `login.config.url.1`

```bash
# Default login configuration file
login.config.url.1=file:${java.home}/lib/security/java.login.config
```

### Paramétrages KERBEROS
* Copier le fichier `keytab` dans le répertoire `/opt/kerberos`

* Editer ou créer le fichier `krb5.conf`

```bash
vim /etc/krb5.conf
```

* Modifier le fichier `krb5.conf`

```bash
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 rdns = false
 default_realm = CNAMTS.LOCAL
 default_ccache_name = KEYRING:persistent:%{uid}
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac

[realms]
 CNAMTS.LOCAL = {
  kdc = 55.243.64.57
  admin_server = 55.243.64.57
}

[domain_realm]
 .cnamts.local = CNAMTS.LOCAL
 cnamts.local = CNAMTS.LOCAL
```

### Paramétrage ALFRESCO
* Editer le fichier `alfresco-global.properties`

```bash
vim /usr/share/tomcat/shared/classes/alfresco-global.properties
```
* Modification de la chaine d'authentification

```bash
authentication.chain=ldap_cpam:ldap,kdc_cpam:kerberos,alfrescoNtlm:alfrescoNtlm
```

* Ajout du paramétrage KERBEROS

```bash
kerberos.authentication.realm=CNAMTS.LOCAL
kerberos.authentication.sso.enabled=true
kerberos.authentication.defaultAdministratorUserNames=admin
kerberos.authentication.user.configEntryName=Alfresco
kerberos.authentication.http.configEntryName=AlfrescoHTTP
kerberos.authentication.http.password=varPwd_AD
kerberos.authentication.authenticateCIFS=false
```
* Pour la variable `kerberos.authentication.http.password`, la valeur `varPwd_AD` est à personnaliser. Il s'agit du mot-de-passe du compte AD "C111301-ALFRESCO-...".
* Il existe 3 comptes AD:
```bash
C111301-ALFRESCO-D      # Pour l'instance de développement
C111301-ALFRESCO-Q      # Pour l'instance de qualification
C111301-ALFRESCO-P      # Pour l'instance de production
```
Chaque compte AD a son propre mot-de-passe. Ils sont disponibles dans KeyPass (commun SASI/SEPSI).

* Commenter le paramétrage de l'authentification externe

```bash
#external.authentication.proxyUserName=
#external.authentication.enabled=true
#external.authentication.defaultAdministratorUserNames=admin
#external.authentication.proxyHeader=X-Alfresco-Remote-User
```

* Redémarrage du serveur TOMCAT

```bash
systemctl restart tomcat
```

A ce niveau de la procédure, il est possible d'accéder à ALFRESCO par les protocoles
`WebdDav` et `AOS` en s'authentifiant par Kerberos.

## Paramétrages du serveur `SHARE`

### Paramétrages JAVA pour Kerberos

#### Modification du fichier `java.login.config`
* Editer ou créer le fichier `java.login.config`

```bash
vim /usr/lib/jvm/java-1.8.0/jre/lib/security/java.login.config
```

* Ajouter le paramétrage suivant

```bash
ShareHTTP
{
   com.sun.security.auth.module.Krb5LoginModule required
   storeKey=true
   useKeyTab=true
   doNotPrompt=true
   keyTab="varKeytab"
   principal="varSpn";
};

```
* Les variables `keytab` et `principal` doivent avoir une valeur en fonction du nom du SPN et du fichier keytab fourni.

* `/!\ Rappel` varKeytab = nom et chemin du fichier keytab généré par le national. Ce dernier met à disposition 3 fichiers .keytab:

```bash
KT-111301-L111301HAALF.keytab        # pour l'instance de production
KT-111301-L111301REVERS-DEV.keytab   # pour l'instance de développement
KT-111301-L111301REVERS-Q.keytab     # pour l'instance de qualification.
```
Exemple: pour le développement,  keyTab="/opt/kerberos/KT-111301-L111301REVERS-DEV.keytab"

* Pour varSpn = nom du principal. Il en existe 3:

```bash
HTTP/ged.cpam-marseille.cnamts.fr@CNAMTS.LOCAL       # pour l'instance de production
HTTP/ged-d.cpam-marseille.cnamts.fr@CNAMTS.LOCAL     # pour l'instance de développement
HTTP/ged-q.cpam-marseille.cnamts.fr@CNAMTS.LOCAL     # pour l'instance de qualification
```
Exemple: pour le développement,  varSpn="HTTP/ged-d.cpam-marseille.cnamts.fr@CNAMTS.LOCAL"


#### Modification du fichier `java.security`
* Editer le fichier `java.security`

```bash
vim /usr/lib/jvm/java-1.8.0/jre/lib/security/java.security
```

* Modifier la variable `login.config.url.1`

```bash
# Default login configuration file
login.config.url.1=file:${java.home}/lib/security/java.login.config
```

### Paramétrages KERBEROS
* Copier le fichier `keytab` dans le répertoire `/opt/kerberos`

* Editer ou créer le fichier `krb5.conf`

```bash
vim /etc/krb5.conf
```

* Modifier le fichier `krb5.conf`

```bash
# Configuration snippets may be placed in this directory as well
includedir /etc/krb5.conf.d/

[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 #forwardable = true
 #proxiable = true
 rdns = false
 default_realm = CNAMTS.LOCAL
 default_ccache_name = KEYRING:persistent:%{uid}
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac

[realms]
 CNAMTS.LOCAL = {
  kdc = 55.243.64.57
  admin_server = 55.243.64.57
}

[domain_realm]
 .cnamts.local = CNAMTS.LOCAL
 cnamts.local = CNAMTS.LOCAL
```

### Désactivation du SSO Cpam Access Master
* Si le `SSO Cpam` a été installé sur l'architecture, il est nécessaire de modifier
le paramétrage de l'application `SHARE` pour ne plus prendre en compte ce plugin.

* Editer le fichier `web.xml`

```bash
vim /var/lib/tomcat/webapps/share/WEB-INF/web.xml
```

* Commenter ou supprimer les sections de `<filter>` suivantes

```bash
    <filter>
        <filter-name>FiltreTestVie</filter-name>
        <filter-class>fr.cnamts.securite.filtres.FiltreTestVie</filter-class>
    </filter>
    <filter>
        <filter-name>securiteAccessMaster</filter-name>
        <filter-class>fr.cnamts.securite.filtres.interfaces.SecuriteAccessMaster</filter-class>
    </filter>
    <filter>
        <filter-name>FiltreSecurite</filter-name>
        <filter-class>fr.cnamts.securite.filtres.FiltreSecurite</filter-class>
        <init-param>
            <param-name>PAGE_ACCUEIL</param-name>
            <param-value>/authen.jsp</param-value>
        </init-param>
        <init-param>
            <param-name>PAGE_REJET</param-name>
            <param-value>/error500.jsp</param-value>
        </init-param>
    </filter>
    <filter>
        <filter-name>UserHeaderFilter</filter-name>
        <filter-class>fr.cnamts.cpam.UserHeaderFilter</filter-class>

        <init-param>
            <param-name>HEADER_NAME</param-name>
            <param-value>X-Alfresco-Remote-User</param-value>
        </init-param>
        <init-param>
            <param-name>ATTR_USERID</param-name>
            <param-value>E</param-value>
        </init-param>
    </filter>
    <filter>
        <filter-name>MemUrlFilter</filter-name>
        <filter-class>fr.cnamts.cpam.MemUrlFilter</filter-class>
    </filter>
```

* Commenter ou supprimer les sections de `<filter-mapping>` suivantes

```bash
    <filter-mapping>
        <filter-name>FiltreTestVie</filter-name>
        <url-pattern>/FiltreTestVie</url-pattern>
    </filter-mapping>
    <filter-mapping>
        <filter-name>MemUrlFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    <filter-mapping>
        <filter-name>securiteAccessMaster</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    <filter-mapping>
        <filter-name>FiltreSecurite</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    <filter-mapping>
        <filter-name>UserHeaderFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
```

### Paramétrage SHARE
* Editer le fichier `share-config-custom.xml`

```bash
vim /usr/share/tomcat/shared/classes/alfresco/web-extension/share-config-custom.xml
```

* Vérifier et/ou modifier le paramétrage des sections suivantes `<config evaluator="string-compare" condition="Remote">`
* En fonction du paramétrage actuel de `SHARE`, il est possible que cette section existe mais soit commentée.
* L'IP des sections `<endpoint-url>` doivent être celle d'Alfresco.

```bash
   <config evaluator="string-compare" condition="Remote">
      <remote>
         <endpoint>
            <id>alfresco-noauth</id>
            <name>Alfresco - unauthenticated access</name>
            <description>Access to Alfresco Repository WebScripts that do not require authentication</description>
            <connector-id>alfresco</connector-id>
            <endpoint-url>http://varIpAlfresco:8080/alfresco/s</endpoint-url>
            <identity>none</identity>
         </endpoint>

         <endpoint>
            <id>alfresco</id>
            <name>Alfresco - user access</name>
            <description>Access to Alfresco Repository WebScripts that require user authentication</description>
            <connector-id>alfresco</connector-id>
            <endpoint-url>http://varIpAlfresco:8080/alfresco/s</endpoint-url>
            <identity>user</identity>
         </endpoint>

         <endpoint>
            <id>alfresco-feed</id>
            <name>Alfresco Feed</name>
            <description>Alfresco Feed - supports basic HTTP authentication via the EndPointProxyServlet</description>
            <connector-id>http</connector-id>
            <endpoint-url>http://varIpAlfresco:8080/alfresco/s</endpoint-url>
            <basic-auth>true</basic-auth>
            <identity>user</identity>
         </endpoint>

         <endpoint>
            <id>alfresco-api</id>
            <parent-id>alfresco</parent-id>
            <name>Alfresco Public API - user access</name>
            <description>Access to Alfresco Repository Public API that require user authentication.
                         This makes use of the authentication that is provided by parent 'alfresco' endpoint.</description>
            <connector-id>alfresco</connector-id>
            <endpoint-url>http://varIpAlfresco:8080/alfresco/api</endpoint-url>
            <identity>user</identity>
         </endpoint>
      </remote>
   </config>
```

* Vérifier et/ou modifier la section `<config evaluator="string-compare" condition="Remote">` suivante:
* L'IP des sections `<endpoint-url>` doivent être celle d'Alfresco.

```bash
   <config evaluator="string-compare" condition="Remote">
      <remote>
        <connector>
            <id>alfrescoCookie</id>
            <name>Alfresco Connector</name>
            <description>Connects to an Alfresco instance using header and cookie-based authentication</description>
            <class>org.alfresco.web.site.servlet.SlingshotAlfrescoConnector</class>
         </connector>

		<connector>
            <id>alfrescoHeader</id>
            <name>Alfresco Connector</name>
            <description>Connects to an Alfresco instance using header and cookie-based authentication</description>
            <class>org.alfresco.web.site.servlet.SlingshotAlfrescoConnector</class>
            <userHeader>SsoUserHeader</userHeader>
         </connector>

         <endpoint>
            <id>alfresco</id>
            <name>Alfresco - user access</name>
            <description>Access to Alfresco Repository WebScripts that require user authentication</description>
            <connector-id>alfrescoCookie</connector-id>
            <endpoint-url>http://varIpAlfresco:8080/alfresco/wcs</endpoint-url>
            <identity>user</identity>
            <external-auth>true</external-auth>
         </endpoint>

         <endpoint>
            <id>alfresco-api</id>
            <parent-id>alfresco</parent-id>
            <name>Alfresco Public API - user access</name>
            <description>Access to Alfresco Repository Public API that require user authentication.
                         This makes use of the authentication that is provided by parent 'alfresco' endpoint.</description>
            <connector-id>alfresco</connector-id>
            <endpoint-url>http://varIpAlfresco:8080/alfresco/api</endpoint-url>
            <identity>user</identity>
            <external-auth>true</external-auth>
         </endpoint>
      </remote>
   </config>
```

* Ajouter et/ou décommenter la section `<config evaluator="string-compare" condition="Kerberos" replace="true">` suivante :

```bash
   <config evaluator="string-compare" condition="Kerberos" replace="true">
      <kerberos>
         <password>varPwd_AD</password>
         <realm>CNAMTS.LOCAL</realm>
         <endpoint-spn>varSpn</endpoint-spn>
         <config-entry>ShareHTTP</config-entry>
        <stripUserNameSuffix>true</stripUserNameSuffix>
      </kerberos>
   </config>

```

* Redémarrage du serveur TOMCAT

```bash
systemctl restart tomcat
```

* Résolution du problème de la validité du ticket KERBEROS

Le paramétrage défini ne permets pas à ALFRESCO de renouveller la validité
du ticket au bout de 24 heures.
Pour contourner ce problème en attendant une solution pérenne il est nécessaire 
de redémarrer le service TOMCAT pour forcer le renouvellement du ticket.
Ce redémarrage est réalisé à partir de la CRONTAB du serveur.

```bash
crontab -e
```
 Ajouter la ligne suivante :
```bash
00 00 * * 1-7 systemctl restart tomcat
```