/ip address add address=10.0.0.1/29 interface=fw0
/ip address add address=10.0.1.1/29 interface=lan0
/ip address add address=10.0.2.1/29 interface=srv0
/ip address add address=10.99.0.1/24 interface=mgmt0
/ip route add dst-address=0.0.0.0/0 gateway=10.0.0.2
/ip route add dst-address=192.168.10.0/24 gateway=10.0.1.3
/ip route add dst-address=192.168.20.0/24 gateway=10.0.2.3
