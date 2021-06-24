import asyncio
from tcputils import *
import random
from time import time


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            seq_no2 = random.randint(0, 0xffff)
            ack_no2 = seq_no+1
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao,seq_no2, ack_no2)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            segmento = make_header(dst_port, src_port, seq_no2, ack_no2, (FLAGS_SYN|FLAGS_ACK))
            self.rede.enviar(fix_checksum(segmento, dst_addr, src_addr), src_addr)


            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.send_base = self.seq_no
        self.fila_envio = []
        self.seq_no += 1
        self.TimeoutInterval = 0.5
        self.EstimatedRTT = None
        self.DevRTT = None
        self.a = 0.125
        self.b = 0.25
        self.cwnd = 1
        self.cwnd_ack = self.ack_no
        self.n_enviados = b''
        self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
        # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def atualiza_timer(self, tempo):
        if tempo:
            sampleRTT = time()- tempo
            if self.EstimatedRTT:
                self.EstimatedRTT = (1-self.a)*self.EstimatedRTT + self.a*sampleRTT
                self.DevRTT = (1-self.b)*self.DevRTT + self.b*abs(sampleRTT-self.EstimatedRTT)
            else:
                self.EstimatedRTT = sampleRTT
                self.DevRTT = sampleRTT/2
            self.TimeoutInterval = self.EstimatedRTT + 4*self.DevRTT
            

    def mudar_de_fila(self):
        livre = (self.cwnd - len(self.fila_envio))*MSS
        if livre <= 0:
            return
        dados = self.n_enviados[:int(livre)]
        self.n_enviados = self.n_enviados[int(livre):]
        for i in range( int(len(dados)/MSS) ):
            ini = i*MSS
            fim = min(len(dados), (i+1)*MSS)

            payload = dados[ini:fim]

            segmento = make_header(self.id_conexao[3],self.id_conexao[1],self.seq_no,self.ack_no, (FLAGS_ACK))+payload
            fixed = fix_checksum(segmento,self.id_conexao[2],self.id_conexao[0])
            self.servidor.rede.enviar(fixed, self.id_conexao[0])
            self.timer.cancel()
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
            self.fila_envio.append([fixed,len(payload), time()])
            self.seq_no += len(payload)


    def _exemplo_timer(self):
        if self.fila_envio:
            self.cwnd = max(self.cwnd/2,1)
            print('oia o loop mae')
            self.servidor.rede.enviar(self.fila_envio[0][0],self.id_conexao[0])
            self.fila_envio[0][2] = None
        
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        if payload:
            if self.ack_no == seq_no:
                self.ack_no += len(payload)
                self.callback(self, payload)
        
        if(flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self, b'')
            self.ack_no += 1

        if( flags &FLAGS_ACK) == FLAGS_ACK and self.send_base < ack_no:
            self.send_base = ack_no
            if ack_no > (self.cwnd_ack + MSS*self.cwnd):
                print('aumentando cwnd')
                self.cwnd_ack = ack_no
                self.cwnd += 1
                print(self.cwnd)
                self.mudar_de_fila()
            if self.fila_envio:
                self.timer.cancel()
                removido = self.fila_envio.pop(0)
                self.atualiza_timer(removido[2])
                self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
        
        if not payload and (flags & FLAGS_FIN) != FLAGS_FIN:
            return
        segmento = make_header(self.id_conexao[3],self.id_conexao[1],self.seq_no,self.ack_no, (FLAGS_ACK))
        self.servidor.rede.enviar(fix_checksum(segmento,self.id_conexao[2],self.id_conexao[0]),self.id_conexao[0])
        
       
        print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        if (self.cwnd*MSS) - (len(self.fila_envio)*MSS) <= 0:
            self.n_enviados = self.n_enviados + dados
            return
        else:
            livre = (self.cwnd*MSS) - (len(self.fila_envio)*MSS)
            self.n_enviados = self.n_enviados + dados[int(livre):]
            dados = dados[:int(livre)]

        if len(dados) <= MSS:
            segmento = make_header(self.id_conexao[3],self.id_conexao[1],self.seq_no,self.ack_no, (FLAGS_ACK))+dados
            fixed = fix_checksum(segmento,self.id_conexao[2],self.id_conexao[0])
            self.servidor.rede.enviar(fixed,self.id_conexao[0])
            print('enviei original')
            self.seq_no += len(dados)
            print('criei timer')
            self.timer.cancel()
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
            self.fila_envio.append([fixed,len(dados), time()])
        
        else:
            if (len(dados)%MSS) == 0 :
                for i in range((len(dados)//MSS)):
                    segmento = make_header(self.id_conexao[3],self.id_conexao[1],self.seq_no,self.ack_no, (FLAGS_ACK))+dados[i*MSS:(i+1)*MSS]
                    fixed = fix_checksum(segmento,self.id_conexao[2],self.id_conexao[0])
                    self.servidor.rede.enviar(fixed, self.id_conexao[0])
                    self.seq_no += len(dados[i*MSS:(i+1)*MSS])
                    self.timer.cancel()
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
                    self.fila_envio.append([fixed,len(dados[i*MSS:(i+1)*MSS]), time()])
            else:
                for i in range((len(dados)//MSS)+1):
                    segmento = make_header(self.id_conexao[3],self.id_conexao[1],self.seq_no,self.ack_no, (FLAGS_ACK))+dados[i*MSS:(i+1)*MSS]
                    fixed = fix_checksum(segmento,self.id_conexao[2],self.id_conexao[0])
                    self.servidor.rede.enviar(fixed, self.id_conexao[0])
                    self.seq_no += len(dados[i*MSS:(i+1)*MSS])
                    self.timer.cancel()
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
                    self.fila_envio.append([fixed, len(dados[i*MSS:(i+1)*MSS]), time()])

        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        segmento = make_header(self.id_conexao[3],self.id_conexao[1],self.seq_no,self.ack_no, (FLAGS_FIN|FLAGS_ACK))
        self.servidor.rede.enviar(fix_checksum(segmento,self.id_conexao[2],self.id_conexao[0]),self.id_conexao[0])
        self.servidor.conexoes.pop(self.id_conexao)
       
