OVPN-Ubuntu-20.04-EC

https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04-EC/main/openvpn.sh?token=AUNZ56M6CFYJO2A73JFIQPDBMW6KK
Установка OpenVPN на Ubuntu 20.04
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04-EC/main/openvpn.sh?token=AUNZ56M6CFYJO2A73JFIQPDBMW6KK
chmod +x 
./openvpn_tls_ubuntu20.04_install.sh
```

Добавление пользователей  
Пользователи лежат на вебстраничке вашего сервера, если веб страничка не работает, то в директории /var/www/html/clients/
```
cd ~ 
./account_manager.sh
```
