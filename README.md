# Dhcp_Rogue-Spoofing

**Estudiante:** Masucci Franco Rincón  
**Matrícula:** 2024-1250  
**Asignatura:** Seguridad de Redes  
**Fecha:** 13/02/2026  

**Link del video:*https://itlaedudo-my.sharepoint.com/:v:/g/personal/20241250_itla_edu_do/IQDqDMBW5A-eQalVSdPDmZXAASxAv5qU3oMLhEoZbmFfHGw*

---

### Descripción y Topología 

El laboratorio se ha desplegado en un entorno virtualizado utilizando **GNS3**, simulando una infraestructura de red corporativa vulnerada desde el interior.

### Detalles de la Topología

<img width="521" height="302" alt="image" src="https://github.com/user-attachments/assets/973f36d1-6b4f-43d8-b383-4c296712c79b" />


**Direccionamiento IP:** Subred `10.12.50.0/24`

**VLAN Afectada:** ID 1

**Servidor DHCP Legítimo:** R1 (10.12.50.1)

**Atacante:** Kali Linux (10.12.50.100)

**Víctima:** PC1 (Cliente DHCP estándar) 



### Objetivo del Script
Este es script lo que hace es que se hace pasar por el router legitimo y cuando una maquina solicita dhcp, la ip de la maquina atacante es el default-gateway de la maquina victima logrando asi el Race condition



### Parámetros Usados
El script utiliza la librería **Scapy** para la inyección de paquetes en capa 2/3.

**IP Asignada:** 10.12.50.150

**Gateway Falso:** 10.12.50.100 **(Dirección del atacante).**

```
ATTACKER_IP = "10.12.50.100"     
VICTIM_IP = "10.12.50.150"         
INTERFACE = "eth0"                
ATTACKER_MAC = get_if_hwaddr()     
src = ATTACKER_MAC
dst = pkt[Ether].src            
src = ATTACKER_IP
dst = "255.255.255.255"           
sport = 67                        
dport = 68                         
op = 2                             
yiaddr = VICTIM_IP                
siaddr = ATTACKER_IP               
chaddr = pkt[BOOTP].chaddr        
xid = pkt[BOOTP].xid               
("message-type", "offer")          
("message-type", "ack")            
("server_id", ATTACKER_IP)         
("router", ATTACKER_IP)            
("subnet_mask", "255.255.255.0")
("name_server", "8.8.8.8")
("lease_time", 3600)
```                     

## Evidencias de Ejecución
## 1- Enviando Offer a la maquina victima
<img width="1909" height="958" alt="image" src="https://github.com/user-attachments/assets/4230a442-6bbe-40e1-abd4-e710a02bf318" />

## 2- Ack en el cliente
<img width="488" height="283" alt="image" src="https://github.com/user-attachments/assets/e359d633-26ea-4edf-8e87-1d3bcb01cd20" />




### Requisitos para utilizar la herramienta.
* Acceso a la red local (Capa 2).
* Privilegios de superusuario para manipulación de puertos RAW (sockets).
* Entorno Python 3 con librerías de red instaladas.



### Medidas de Mitigación
Para remediar esta vulnerabilidad, se debe implementar **DHCP Snooping** en los switches de acceso.

1.  Activar DHCP Snooping globalmente.
2.  Configurar los puertos de usuarios como **Untrusted** (No confiables).
3.  Configurar el puerto del Router legítimo como **Trusted** (Confiable).

```bash
! Configuración en Switch Cisco
ip dhcp snooping
ip dhcp snooping vlan 2295
interface e0/0
 description UPLINK_ROUTER
 ip dhcp snooping trust
