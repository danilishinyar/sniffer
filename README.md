# Анализатор трафика
## Используемые библиотеки
* Scapy
## Реализованные функции
* Выбор сетевого интерфейса для сниффинга
* Выбор фильтра для анализа трафика
* Вывод информации, содержащейся в пакетах, в читабельном виде
* Вывод таблицы с IP и MAC адресами устройств в сети
* ARP-спуфинг
  * Для его корректной работы необходимо выполнить следующие комманды:
    *` sudo -i

    * echo 1 > /proc/sys/net/ipv4/ip_forward

    * iptables --flush

    * iptables -t nat --flush

    * iptables --zero

    * iptables -A FORWARD --in-interface wlp2s0  -j ACCEPT

    * iptables -t nat --append POSTROUTING --out-interface YOUR INTERFACE MASQUERADE`

## Пример работы
![](gif/howitworks-1.gif)
