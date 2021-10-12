Установка OpenVPN - EC на Ubuntu 20.04
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04-EC/main/openvpn.sh -O openvpn-install.sh
chmod +x 
./openvpn-install.sh
```

Добавление пользователей  
Пользователи лежат на вебстраничке вашего сервера, если веб страничка не работает, то в директории /root/
```
cd ~ 
./account_manager.sh
```
