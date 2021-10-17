Данный скрипт устанавливает серверную конфигурацию OpenVPN.  
Особенности:   
1. Использование эллиптических кривых в качестве алгоритма сертификатов.  
2. Алгоритм обмена ключей - ECDH. Взамен типичному DH.  
3. Использование TLS-crypt min 1.2  
4. Сатичесские адреса клиентов  

Установка OpenVPN - EC на Ubuntu 20.04
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04-EC/main/openvpn.sh -O openvpn-install.sh --secure-protocol=TLSv1
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Добавление пользователей  
Пользователи лежат на вебстраничке вашего сервера, если веб страничка не работает, то в директории /root/
```
cd ~ 
./account_manager.sh
```
