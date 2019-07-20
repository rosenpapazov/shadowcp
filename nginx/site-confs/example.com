#SSL redirect

server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

#SSL

server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name example.com;
        access_log /var/log/nginx/example.com-access.log;
        error_log /var/log/nginx/example.com-error.log;
    if ($host != $server_name) {
        #return 404 "this is an invalid request";
        return	444;
    }

    rewrite_log on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;#
    satisfy any; 
    auth_basic "Administrator’s Area";
    auth_basic_user_file .htpasswd;
    allow 4.3.2.1/32;
    allow 1.2.3.0/24;
    allow 200x:xx:xx:xx::/64;
    keepalive_timeout 70;
    
    ssl_certificate example.com/fullchain.pem;
    ssl_certificate_key example.com/privkey.pem;
#   ssl_ciphers 'HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128';
    ssl_ciphers 'AES256+EECDH:AES256+EDH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128';
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https://example.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://example.com https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; style-src 'self' 'unsafe-inline' https://example.com https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://example.com https://themes.googleusercontent.com; frame-src https://example.com https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com; object-src https://example.com 'none'";
    #add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.zendesk.com; img-src * data: https://ssl.google-analytics.com https://s-static.ak.facebook.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; object-src 'none'; frame-src https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com"

    add_header Referrer-Policy "no-referrer";
    ssl_ecdh_curve secp384r1;
    ssl_stapling_verify on;
    ssl_prefer_server_ciphers on;
    ssl_dhparam dhparam.pem;
    resolver 8.8.8.8 8.8.4.4;
    ssl_stapling on;
    ssl_trusted_certificate example.com/chain.pem;


#location /{
#
#    default_type text/plain;
#
#    return 200 "$remote_addr\n";
#
#}    
    
location / {
        proxy_pass http://127.0.0.1:2380/smokeping/;
	proxy_set_header Host $host;
	proxy_set_header X-Real-IP $remote_addr; 
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cookie_path /smokeping/ /;
	}
location /abuseipdb-verification.html {
        return 200 "abuseipdb-verification-8BMkNzSy";
}



}
