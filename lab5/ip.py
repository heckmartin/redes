from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = None
        self.ident = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = \
            read_ipv4_header(datagrama)
            if ttl == 1:
                self.send_ICMP(datagrama, src_addr)
                return
            ttl -= 1
            verihl = (4<< 4) | 5
            checked = 0
            segment = struct.pack('!BBHHHBBH',verihl,dscp|ecn,20+len(payload),self.ident,(flags<<13)|frag_offset,ttl,proto,checked) + str2addr(src_addr)+str2addr(dst_addr)
            checked = calc_checksum(segment)
            datagrama = struct.pack('!BBHHHBBH',verihl,dscp|ecn,20+len(payload),self.ident,(flags<<13)|frag_offset,ttl,proto,checked) + str2addr(src_addr)+str2addr(dst_addr)+payload

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        val, = struct.unpack('!I', str2addr(dest_addr))
        valid_size = -1
        cidr = None
        for t in self.tabela:
            valid = int(t[0].split('/')[1])
            jump = 32 - valid
            net, = struct.unpack('!I', str2addr(t[0].split('/')[0]))
            if (val >> jump << jump) == (net >> jump << jump):
                if valid_size < valid:
                    valid_size = valid
                    cidr = t[1]
        if cidr:
            return cidr


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback
    
    def send_ICMP(self, datagrama, dst_addr):
        checked = 0
        icmp = struct.pack('!BBHI', 11, 0, checked,0)+datagrama[:28]
        checked = calc_checksum(icmp)
        icmp = struct.pack('!BBHI', 11, 0, checked,0)+datagrama[:28]
        self.enviar(icmp,dst_addr, IPPROTO_ICMP)

    def enviar(self, segmento, dest_addr, protocol = 6):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        verihl = (4<< 4) | 5
        dscpecn = 0 << 7
        total_len = 20 + len (segmento)
        id = self.ident
        flagsfrag = (0 << 15) | 0
        ttl = 64
        checked = 0
        segment = struct.pack('!BBHHHBBH',verihl,dscpecn,total_len,id,flagsfrag,ttl,protocol,checked)+str2addr(self.meu_endereco)+str2addr(dest_addr)
        checked = calc_checksum(segment)
        datagrama = struct.pack('!BBHHHBBH',verihl,dscpecn,total_len,id,flagsfrag,ttl,protocol,checked)+str2addr(self.meu_endereco)+str2addr(dest_addr)+segmento
        self.enlace.enviar(datagrama, next_hop)
