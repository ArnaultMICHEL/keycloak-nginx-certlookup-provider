Provider NGINX for Keycloak
==========================

NGINX can be used as a reverse proxy in front of the Keycloak server or clusters.
That's what we use with our K8s clusters powered by [Ingress NGINX controller](https://github.com/kubernetes/ingress-nginx/)

Abstract
--------

The provider allows to extract X.509 client certificate from http header, setted by NGINX reverse proxy acting as TLS server.

As NGINX is not able (at this time) to forward the entire client certificate chain, Keycloak will rebuild the entire chain with it's own truststore.

Pre Requisites : Add NGINX Reverse Proxy
----------------------------------------

First, you need Keycloak version 3.4.1 minimum.
You do not need this provider with version 4.8.0 or later : it's already included in Keycloak distribution ( see [PR 5796](https://github.com/keycloak/keycloak/pull/5796) ).

You need to :

1. install, configure, and run NGINX as a reverse proxy.

The minimal configuration must include this :
```txt
 server { 
    ...
    ssl_client_certificate                  path-to-my-trusted-cas-list-for-client-auth.pem;
    ssl_verify_client                       on|optional_no_ca;
    ssl_verify_depth                        2;
    ...
    location / {
      ...
      proxy_set_header ssl-client-cert        $ssl_client_escaped_cert;
      ...
    }
    ...
}
```

Please note that :
 * optional_no_ca must be used if you want to trust one subCA and not the others (issued by the same root CA)
See [this article](https://stackoverflow.com/questions/8431528/nginx-ssl-certificate-authentication-signed-by-intermediate-ca-chain)
 * ssl_verify_depth must be adapted, depending on your CA architecture
 * path-to-my-trustyed-cas-list-for-client-auth.pem must include all your CA/SubCA Certificates needed for client authentication.


<details>
<summary>my nginx.conf for local tests, click me to expand</summary>
<p>

```conf
worker_processes  1;

#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;
	
    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    # HTTPS server, that redirect all on HTTPS
    server {

        listen 80 default_server;
        listen [::]:80 default_server;
		
        server_name  localhost;

		return 301 https://$host$request_uri;
		
    }


    # HTTPS server
    #
	server {
		listen       443 ssl http2;
		server_name  localhost;

		ssl_certificate        nginx-selfsigned.crt;
		ssl_certificate_key    nginx-selfsigned.key;
		ssl_client_certificate my-root-cas-for-client-auth.pem;
		ssl_verify_client      optional_no_ca;
		ssl_verify_depth       2;
		ssl_stapling                            on;
		ssl_stapling_verify                     on;
		
		ssl_session_cache    shared:SSL:1m;
		ssl_session_timeout  5m;

		ssl_ciphers  HIGH:!aNULL:!MD5;
		ssl_prefer_server_ciphers  on;

		location / {

			port_in_redirect off;

			proxy_set_header X-Forwarded-For        $remote_addr;

			proxy_set_header Host                   $host;
			
			proxy_set_header X-Forwarded-Host       $host;
			proxy_set_header X-Forwarded-Port       443;
			proxy_set_header X-Forwarded-Proto      $scheme;

			proxy_set_header X-Original-URI         $request_uri;
			proxy_set_header X-Request-ID           $request_id;
			proxy_set_header X-Real-IP $remote_addr;

			proxy_set_header ssl-client-cert        $ssl_client_escaped_cert;
			proxy_set_header ssl-client-verify      $ssl_client_verify;
			proxy_set_header ssl-client-subject-dn  $ssl_client_s_dn;
			proxy_set_header ssl-client-issuer-dn   $ssl_client_i_dn;

			# Custom headers to proxied server

			proxy_connect_timeout                   60s;
			proxy_send_timeout                      60s;
			proxy_read_timeout                      60s;

			proxy_buffering                         "off";
			proxy_buffer_size                       "4k";
			proxy_buffers                           4 "4k";
			proxy_request_buffering                 "on";

			proxy_http_version                      1.1;

			proxy_cookie_domain                     off;
			proxy_cookie_path                       off;

			client_max_body_size                    "1m";
			
			# In case of errors try the next upstream server before returning an error
			proxy_next_upstream                     error timeout invalid_header http_502 http_503 http_504;
			proxy_next_upstream_tries               0;

			proxy_pass http://127.0.0.1:8080/;

			proxy_redirect                          off;

		}
	}
}
```

</p>
</details>


Compilation
-----------

You can change Keycloak version if needed in pom.xml > parent > version

```bash
mvn install
```


Installation
------------

Copy the jar keycloak-x509-provider-nginx-X.Y.Z.Final.jar, from target/\*.jar if you compile it, to the directory keycloak-X.X.X.Final/providers


Configuration
-------------

Modify your keycloak-X.X.X.Final/standalone/configuratiuon/standalone[-ha].xml with :

1. Configure X.509 client authentication on a new [Browser Flow](https://www.keycloak.org/docs/latest/server_admin/index.html#adding-x-509-client-certificate-authentication-to-a-browser-flow)

2. Add [NGINX certificate lookup provider](https://www.keycloak.org/docs/latest/server_admin/index.html#nginx-certificate-lookup-provider)

```XML
<spi name="x509cert-lookup">
    <default-provider>nginx</default-provider>
    <provider name="nginx" enabled="true">
        <properties>
            <property name="sslClientCert" value="ssl-client-cert"/>
            <property name="sslCertChainPrefix" value="CERT_CHAIN"/>
            <property name="certificateChainLength" value="2"/>
        </properties>
    </provider>
</spi>
```

3. Configure [Keycloak truststore](https://www.keycloak.org/docs/latest/server_installation/index.html#_truststore), and add your own CA/SubCA Certificates with [JDK Keytool(https://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html), [Keystore explorer](https://keystore-explorer.org/), or yet another Keystore managment tool.

4. Configure Keycloak behind a reverse proxy :
  * [Identifying Client IP Addresses](https://www.keycloak.org/docs/4.6/server_installation/#identifying-client-ip-addresses)
  * [Enable HTTPS/SSL with a Reverse Proxy](https://www.keycloak.org/docs/4.6/server_installation/#enable-https-ssl-with-a-reverse-proxy)

5. Restart Keycloak and verify [here](ihttps://myKeycloakDNS/auth/admin/master/console/#/server-info/providers) that the x509cert-lookup provider is correctly loaded


Troubleshooting
---------------

1. How can i see the http headers received from the reverse proxy?

Simply activate [RequestDumpingHandler](https://mirocupak.com/logging-requests-with-undertow/) to dump HTTP headers in Keycloak server.log file 
By this way, you should identify the correct header and validate if the certificate format is 

2. Increasing log level information on Keycloak

 * dynamically with JBoss CLI : 
```bash
$ jboss-cli.sh --connect
/subsystem=logging/logger=org.keycloak.services.x509:write-attribute(name=level,value=TRACE)  
/subsystem=logging/logger=org.keycloak.authentication.authenticators.x509:write-attribute(name=level,value=TRACE)  
```

 * statically with wildfly configuration file : keycloak-X.X.X.Final/standalone/configuration/standalone[-ha].xml

```XML
...
    <profile>
        <subsystem xmlns="urn:jboss:domain:logging:3.0">
...
            <logger category="org.keycloak.services.x509">
                <level name="TRACE"/>
            </logger>
            <logger category="org.keycloak.authentication.authenticators.x509">
                <level name="TRACE"/>
            </logger>
...
    </profile>
```

Logs are in keycloak-X.X.X.Final/standalone/log/server.log

3. I have a lot of process and file to start/monitor...

I crerate this windows script that start everything, that helps me to save time :)

<details>
<summary>Batch script that start Keycloak (debug mode), Nginx RP, jboss admin cli, chrome on admin and cert test </summary>
<p>

```
@echo off

set JBOSS_HOME=C:\Produits\FRAMDEV\server\keycloak-4.6.0.Final
set NGINX_HOME=C:\Produits\FRAMDEV\server\nginx-1.14.1

echo.
echo.
echo Starting Keycloak 4.6.0
c:
cd %JBOSS_HOME%\bin
del /Q %JBOSS_HOME%\standalone\log\server.log
start standalone.bat --debug -Dkeycloak.x509cert.lookup.provider=nginx -Djboss.socket.binding.port-offset=1000

echo.
echo.
echo Stopping existing NGINX processus
taskkill /IM nginx.exe /F
echo.
echo.
echo   Starting nginx RP
cd %NGINX_HOME%
start cmd /C nginx.exe

timeout 30

echo.
echo.
echo Starting JBOSS-cli for Keycloak 4.6.0
cd %JBOSS_HOME%\bin
start jboss-cli.bat --connect  --controller=127.0.0.1:10990
cd -

echo.
echo.
echo Keycloak URLs :
echo   - Admin without TLS : http://localhost:9080/auth/admin
echo   - X.509 client auth test : https://localhost/auth/realms/certtest/account
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" https://localhost/auth/realms/certtest/account http://localhost:9080/auth/admin/

echo.
echo.
echo Opening logs files in Notepadd++ : 
"C:\Program Files (x86)\Notepad++\notepad++.exe" %JBOSS_HOME%\standalone\configuration\standalone.xml %NGINX_HOME%\conf\nginx.conf %NGINX_HOME%\logs\error.log %JBOSS_HOME%\standalone\logs\server.log

```

</p>
</details>


References
----------

 * https://mirocupak.com/logging-requests-with-undertow/
 * https://www.keycloak.org/docs/latest/server_installation/index.html#_truststore
 * http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client

