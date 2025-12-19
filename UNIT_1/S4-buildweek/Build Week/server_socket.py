import socket
import struct
import sys # Necessario per uscire in caso di errore

# Questo programma DEVE essere eseguito con 'sudo' su Linux (Kali) perché
# ha bisogno di permessi speciali per aprire un raw socket e vedere tutto il traffico!

def inizia_a_sniffare():
    #Setup iniziale del socket e ciclo principale di cattura dei pacchetti.
    try:
        # 1. Creazione del Raw Socket
        # AF_PACKET: Cattura pacchetti a livello Data-Link
        # SOCK_RAW: Prende i dati grezzi
        # 0x0003 (ETH_P_ALL): Dice al Kernel "dammi tutti i pacchetti!"
        # socket.ntohs(0x0003) assicura il corretto ordine dei byte.
        sniffer_socket = socket.socket(
            socket.AF_PACKET, 
            socket.SOCK_RAW, 
            socket.ntohs(0x0003)
        )
        print("Socket RAW creato con successo! Ora stiamo ascoltando il traffico...")

    except socket.error as errore:
        print("ERRORE: Non è stato possibile creare il socket.")
        print(f"Messaggio di errore: {errore}")
        print("RICORDA: Devi eseguire lo script con 'sudo' (privilegi di root)!")
        sys.exit() # Usciamo se non possiamo creare il socket

    # 2. Ciclo infinito di cattura
    while True:
        try:
            # Cattura il pacchetto (fino a 65565 byte) e l'indirizzo dell'interfaccia
            pacchetto_completo, indirizzo_interfaccia = sniffer_socket.recvfrom(65565)
            
            # Quando usiamo AF_PACKET, i dati includono l'Header Ethernet (14 byte).
            # Dobbiamo saltarlo per arrivare all'Header IP.
            # I dati IP iniziano dal 15° byte (indice [14])
            dati_ip = pacchetto_completo[14:]

            analizza_pacchetto_ip(dati_ip)

        except KeyboardInterrupt:
            print("\nSniffer interrotto dall'utente (Ctrl+C). Arrivederci!")
            break
        except Exception as e:
            print(f"Errore sconosciuto durante la ricezione: {e}")
            
# --- FUNZIONI DI ANALISI ---

def analizza_pacchetto_ip(dati_pacchetto):
    """
    Decodifica l'Header IP (Livello 3).
    """
    
    # Header IP standard è di 20 byte
    HEADER_IP_LENGTH = 20
    if len(dati_pacchetto) < HEADER_IP_LENGTH:
        return # Pacchetto troppo corto, ignoralo

    # Formato di decodifica (20 byte): !BBHHHBBH4s4s
    # '!' = Ordine di Rete (Big Endian)
    # B = 1 Byte, H = 2 Byte, 4s = Stringa di 4 Byte
    try:
        header_ip = dati_pacchetto[:HEADER_IP_LENGTH]
        dati_header_ip = struct.unpack('!BBHHHBBH4s4s', header_ip)
    except struct.error:
        print("Errore nella decodifica base dell'Header IP.")
        return

    # 1. Estrarre la Lunghezza dell'Header IP (IHL)
    vers_ihl = dati_header_ip[0]
    # IHL è la parte bassa del primo byte. (IHL & 0xF)
    # Moltiplicato per 4 per avere la lunghezza in byte.
    ihl_in_bytes = (vers_ihl & 0xF) * 4
    
    # 2. Estrarre il Protocollo
    protocollo_numero = dati_header_ip[6] # 6=TCP, 17=UDP, 1=ICMP
    
    # 3. Estrarre gli Indirizzi IP
    ip_sorgente_byte = dati_header_ip[8]
    ip_destinazione_byte = dati_header_ip[9]
    
    # Conversione in formato leggibile (dotted-decimal)
    ip_sorgente = socket.inet_ntoa(ip_sorgente_byte)
    ip_destinazione = socket.inet_ntoa(ip_destinazione_byte)

    # 4. Estrarre la Lunghezza Totale
    lunghezza_pacchetto_totale = dati_header_ip[2]
        
    # I dati per il livello successivo (TCP/UDP) iniziano subito dopo l'Header IP.
    dati_livello_trasporto = dati_pacchetto[ihl_in_bytes:]
    print(protocollo_numero)
    
    # 5. Chiama la funzione di analisi del protocollo di trasporto
    while protocollo_numero == 6 or protocollo_numero == 17:
            # --- STAMPA INFORMAZIONI IP ---
            print("\n" + "="*60)
            print(f"Pacchetto IP - Lunghezza Totale: {lunghezza_pacchetto_totale} byte")
            print(f"-> Mittente IP: {ip_sorgente}")
            print(f"-> Destinatario IP: {ip_destinazione}")
            if protocollo_numero == 6:
                print("-> Protocollo di Trasporto: TCP (6)")
                analizza_pacchetto_tcp(dati_livello_trasporto, ihl_in_bytes, lunghezza_pacchetto_totale)
            elif protocollo_numero == 17:
                print("-> Protocollo di Trasporto: UDP (17)")
                analizza_pacchetto_udp(dati_livello_trasporto)
            elif protocollo_numero == 1:
                print("-> Protocollo di Trasporto: ICMP (1)") 
            else:
                continue
        


def analizza_pacchetto_tcp(dati_tcp, lunghezza_ip, lunghezza_totale):
    
    #Decodifica l'Header TCP (Livello 4).
    HEADER_TCP_LENGTH = 20
    if len(dati_tcp) < HEADER_TCP_LENGTH:
        print("  [TCP] Errore: Dati TCP troppo corti.")
        return

    # Formato di decodifica (primi 20 byte): !HHLLBBHHH
    # H = Porta Sorgente (2 byte), H = Porta Destinazione (2 byte)
    try:
        dati_header_tcp = struct.unpack('!HHLLBBHHH', dati_tcp[:HEADER_TCP_LENGTH])
    except struct.error:
        print("  [TCP] Errore nella decodifica dell'Header TCP.")
        return

    porta_sorgente = dati_header_tcp[0]
    porta_destinazione = dati_header_tcp[1]
    
    # Il campo 'Data Offset/Flags' (dati_header_tcp[4]) contiene la lunghezza dell'Header TCP.
    # Si trova nei primi 4 bit del 5° campo (di 2 byte), poi moltiplicato per 4.
    offset_flags = dati_header_tcp[4]
    lunghezza_tcp_in_bytes = (offset_flags >> 12) * 4
    
    lunghezza_dati_utili = lunghezza_totale - lunghezza_ip - lunghezza_tcp_in_bytes

    print(f"  [TCP] Porta Sorgente: {porta_sorgente} -> Porta Destinazione: {porta_destinazione}")
    print(f"  [TCP] Header Lunghezza: {lunghezza_tcp_in_bytes} byte")
    print(f"  [Dati] Lunghezza Dati Utili (Payload): {lunghezza_dati_utili} byte")


def analizza_pacchetto_udp(dati_udp):
    
    #Decodifica l'Header UDP (Livello 4).
    HEADER_UDP_LENGTH = 8
    if len(dati_udp) < HEADER_UDP_LENGTH:
        print("  [UDP] Errore: Dati UDP troppo corti.")
        return

    # Formato di decodifica (8 byte): !HHHH
    # H = Porta Sorgente, H = Porta Destinazione, H = Lunghezza UDP
    try:
        dati_header_udp = struct.unpack('!HHHH', dati_udp[:HEADER_UDP_LENGTH])
    except struct.error:
        print("  [UDP] Errore nella decodifica dell'Header UDP.")
        return

    porta_sorgente = dati_header_udp[0]
    porta_destinazione = dati_header_udp[1]
    lunghezza_datagramma_udp = dati_header_udp[2] # Include l'header UDP (8 byte)

    lunghezza_dati_utili = lunghezza_datagramma_udp - 8

    print(f"  [UDP] Porta Sorgente: {porta_sorgente} -> Porta Destinazione: {porta_destinazione}")
    print(f"  [UDP] Datagramma Lunghezza Totale: {lunghezza_datagramma_udp} byte")
    print(f"  [Dati] Lunghezza Dati Utili (Payload): {lunghezza_dati_utili} byte")


if __name__ == "__main__":
    inizia_a_sniffare()