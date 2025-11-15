#!/usr/bin/env python3
"""
Cliente do Antivírus Distribuído
Escaneia arquivos localmente mas consulta servidor para análise
"""

import os
import hashlib
import time
import psutil
import requests
import uuid
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

class AntivirusDistribuidoCliente:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.client_id = str(uuid.uuid4())[:8]
        self.signatures = {}
        self.scan_results = {
            'total_files': 0,
            'infected_files': 0,
            'clean_files': 0,
            'suspicious_files': 0,
            'scan_time': 0,
            'threats_found': [],
            'scan_speed': 0,
            'avg_time_per_file': 0,
            'total_bytes_scanned': 0,
            'network_requests': 0,
            'network_bytes_sent': 0,
            'network_bytes_received': 0,
            'avg_network_latency': 0,
            'detection_methods': {'hash': 0, 'pattern': 0, 'behavioral': 0, 'cloud': 0},
            'threat_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'file_types_scanned': {},
            'server_response_times': [],
            'largest_file': {'name': '', 'size': 0},
            'smallest_file': {'name': '', 'size': float('inf')}
        }
        self.scan_times = []
        
        print(f"{Fore.CYAN}Cliente ID: {self.client_id}")
        self.check_server_connection()
    
    def check_server_connection(self):
        """Verifica conexão com o servidor"""
        try:
            response = requests.get(f'{self.server_url}/health', timeout=5)
            if response.status_code == 200:
                info = response.json()
                print(f"{Fore.GREEN}✓ Conectado ao servidor")
                print(f"  Versão: {info['version']}")
                print(f"  Assinaturas: {info['total_signatures']}")
                print(f"  Última atualização: {info['last_update']}")
                return True
        except Exception as e:
            print(f"{Fore.RED}✗ Erro ao conectar ao servidor: {e}")
            print(f"{Fore.YELLOW}⚠ Certifique-se de que o servidor está rodando!")
            return False
    
    def download_signatures(self):
        """Baixa assinaturas do servidor"""
        try:
            response = requests.get(
                f'{self.server_url}/signatures',
                params={'client_id': self.client_id},
                timeout=5
            )
            if response.status_code == 200:
                self.signatures = response.json()
                print(f"{Fore.GREEN}✓ Assinaturas atualizadas: {len(self.signatures.get('malware', {}))} assinaturas")
                return True
        except Exception as e:
            print(f"{Fore.RED}✗ Erro ao baixar assinaturas: {e}")
        return False
    
    def calculate_hash(self, filepath):
        """Calcula o hash MD5 de um arquivo"""
        md5 = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
            return md5.hexdigest()
        except Exception as e:
            return None
    
    def get_content_preview(self, filepath, max_size=1024):
        """Obtém uma prévia do conteúdo do arquivo"""
        try:
            with open(filepath, 'rb') as f:
                return f.read(max_size).decode('utf-8', errors='ignore')
        except:
            return ''
    
    def scan_file_remote(self, filepath):
        """Envia arquivo para análise no servidor com métricas detalhadas"""
        request_start = time.time()
        
        file_hash = self.calculate_hash(filepath)
        if not file_hash:
            return None
        
        content_preview = self.get_content_preview(filepath)
        
        # Calcular tamanho da requisição
        request_data = {
            'hash': file_hash,
            'name': str(filepath),
            'client_id': self.client_id,
            'content_preview': content_preview
        }
        import json
        request_size = len(json.dumps(request_data).encode('utf-8'))
        self.scan_results['network_bytes_sent'] += request_size
        
        try:
            self.scan_results['network_requests'] += 1
            response = requests.post(
                f'{self.server_url}/scan',
                json=request_data,
                timeout=10
            )
            
            request_time = time.time() - request_start
            self.scan_results['server_response_times'].append(request_time)
            
            if response.status_code == 200:
                response_size = len(response.content)
                self.scan_results['network_bytes_received'] += response_size
                return response.json()
        except Exception as e:
            print(f"{Fore.RED}✗ Erro ao escanear {filepath}: {e}")
        
        return None
    
    def scan_file(self, filepath):
        """Escaneia um arquivo individual com métricas detalhadas"""
        file_start_time = time.time()
        self.scan_results['total_files'] += 1
        
        try:
            file_size = Path(filepath).stat().st_size
            self.scan_results['total_bytes_scanned'] += file_size
            
            # Rastrear maior e menor arquivo
            if file_size > self.scan_results['largest_file']['size']:
                self.scan_results['largest_file'] = {'name': str(filepath), 'size': file_size}
            if file_size < self.scan_results['smallest_file']['size']:
                self.scan_results['smallest_file'] = {'name': str(filepath), 'size': file_size}
            
            # Rastrear tipo de arquivo
            file_ext = Path(filepath).suffix or 'sem_extensão'
            self.scan_results['file_types_scanned'][file_ext] = self.scan_results['file_types_scanned'].get(file_ext, 0) + 1
        except:
            file_size = 0
        
        # Análise remota
        result = self.scan_file_remote(filepath)
        
        if result:
            if not result['clean']:
                severity = result.get('severity', 'medium')
                
                print(f"{Fore.RED}✗ AMEAÇA DETECTADA: {filepath}")
                print(f"  Tipo: {result['threat']}")
                print(f"  Severidade: {severity.upper()}")
                if result['recommendations']:
                    print(f"  Recomendações: {', '.join(result['recommendations'])}")
                
                # Determinar se é infectado ou suspeito
                if severity in ['critical', 'high']:
                    self.scan_results['infected_files'] += 1
                else:
                    self.scan_results['suspicious_files'] += 1
                
                # Método de detecção
                if 'hash' in result.get('method', '').lower():
                    self.scan_results['detection_methods']['hash'] += 1
                elif 'pattern' in result['threat'].lower():
                    self.scan_results['detection_methods']['pattern'] += 1
                else:
                    self.scan_results['detection_methods']['cloud'] += 1
                
                # Severidade
                self.scan_results['threat_severity'][severity] = self.scan_results['threat_severity'].get(severity, 0) + 1
                
                self.scan_results['threats_found'].append({
                    'file': str(filepath),
                    'threat': result['threat'],
                    'severity': severity,
                    'size': file_size,
                    'recommendations': result.get('recommendations', [])
                })
            else:
                print(f"{Fore.GREEN}✓ Limpo: {filepath}")
                self.scan_results['clean_files'] += 1
        else:
            print(f"{Fore.YELLOW}⚠ Não foi possível analisar: {filepath}")
        
        # Registrar tempo
        file_scan_time = time.time() - file_start_time
        self.scan_times.append(file_scan_time)
    
    def scan_directory(self, directory):
        """Escaneia um diretório recursivamente"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}ANTIVÍRUS DISTRIBUÍDO - Iniciando Scan")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        # Baixar assinaturas atualizadas
        self.download_signatures()
        print()
        
        start_time = time.time()
        process = psutil.Process()
        start_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        path = Path(directory)
        if path.is_file():
            self.scan_file(path)
        else:
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = Path(root) / file
                    self.scan_file(filepath)
        
        end_time = time.time()
        end_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        self.scan_results['scan_time'] = end_time - start_time
        self.scan_results['memory_used'] = end_memory - start_memory
        
        # Calcular métricas adicionais
        if self.scan_results['scan_time'] > 0:
            self.scan_results['scan_speed'] = self.scan_results['total_files'] / self.scan_results['scan_time']
        if self.scan_results['total_files'] > 0:
            self.scan_results['avg_time_per_file'] = self.scan_results['scan_time'] / self.scan_results['total_files']
        if self.scan_results['server_response_times']:
            self.scan_results['avg_network_latency'] = sum(self.scan_results['server_response_times']) / len(self.scan_results['server_response_times'])
        
        self.print_results()
        self.print_server_stats()
    
    def print_results(self):
        """Imprime os resultados detalhados do scan"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}RESULTADO DO SCAN - ANTIVÍRUS DISTRIBUÍDO")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        # Estatísticas gerais
        print(f"{Fore.WHITE}📊 ESTATÍSTICAS GERAIS:")
        print(f"   Total de arquivos escaneados: {self.scan_results['total_files']}")
        print(f"   {Fore.GREEN}Arquivos limpos: {self.scan_results['clean_files']}")
        print(f"   {Fore.RED}Arquivos infectados: {self.scan_results['infected_files']}")
        print(f"   {Fore.YELLOW}Arquivos suspeitos: {self.scan_results['suspicious_files']}")
        
        # Performance
        print(f"\n{Fore.WHITE}⚡ PERFORMANCE:")
        print(f"   Tempo total de scan: {self.scan_results['scan_time']:.3f}s")
        print(f"   Velocidade: {self.scan_results['scan_speed']:.2f} arquivos/segundo")
        print(f"   Tempo médio por arquivo: {self.scan_results['avg_time_per_file']*1000:.2f}ms")
        if self.scan_times:
            print(f"   Arquivo mais rápido: {min(self.scan_times)*1000:.2f}ms")
            print(f"   Arquivo mais lento: {max(self.scan_times)*1000:.2f}ms")
        
        # Rede
        print(f"\n{Fore.WHITE}🌐 ESTATÍSTICAS DE REDE:")
        print(f"   Requisições ao servidor: {self.scan_results['network_requests']}")
        print(f"   Dados enviados: {self.scan_results['network_bytes_sent']/1024:.2f} KB")
        print(f"   Dados recebidos: {self.scan_results['network_bytes_received']/1024:.2f} KB")
        print(f"   Latência média: {self.scan_results['avg_network_latency']*1000:.2f}ms")
        if self.scan_results['server_response_times']:
            print(f"   Resposta mais rápida: {min(self.scan_results['server_response_times'])*1000:.2f}ms")
            print(f"   Resposta mais lenta: {max(self.scan_results['server_response_times'])*1000:.2f}ms")
        
        # Recursos
        print(f"\n{Fore.WHITE}💾 USO DE RECURSOS:")
        print(f"   Memória utilizada: {self.scan_results['memory_used']:.2f} MB")
        total_mb = self.scan_results['total_bytes_scanned'] / 1024 / 1024
        print(f"   Total de dados escaneados: {total_mb:.2f} MB")
        if self.scan_results['scan_time'] > 0:
            throughput = total_mb / self.scan_results['scan_time']
            print(f"   Taxa de transferência: {throughput:.2f} MB/s")
        
        # Tipos de arquivo
        if self.scan_results['file_types_scanned']:
            print(f"\n{Fore.WHITE}📁 TIPOS DE ARQUIVO:")
            for ext, count in sorted(self.scan_results['file_types_scanned'].items(), key=lambda x: x[1], reverse=True):
                print(f"   {ext}: {count} arquivo(s)")
        
        # Tamanhos
        print(f"\n{Fore.WHITE}📏 TAMANHOS:")
        if self.scan_results['largest_file']['size'] > 0:
            print(f"   Maior arquivo: {Path(self.scan_results['largest_file']['name']).name} ({self.scan_results['largest_file']['size']/1024:.2f} KB)")
        if self.scan_results['smallest_file']['size'] < float('inf'):
            print(f"   Menor arquivo: {Path(self.scan_results['smallest_file']['name']).name} ({self.scan_results['smallest_file']['size']} bytes)")
        
        # Métodos de detecção
        if sum(self.scan_results['detection_methods'].values()) > 0:
            print(f"\n{Fore.WHITE}🔍 MÉTODOS DE DETECÇÃO:")
            for method, count in self.scan_results['detection_methods'].items():
                if count > 0:
                    print(f"   {method.title()}: {count} detecção(ões)")
        
        # Severidade
        if sum(self.scan_results['threat_severity'].values()) > 0:
            print(f"\n{Fore.WHITE}⚠️  SEVERIDADE DAS AMEAÇAS:")
            severity_colors = {'critical': Fore.RED, 'high': Fore.MAGENTA, 'medium': Fore.YELLOW, 'low': Fore.BLUE}
            for level, count in self.scan_results['threat_severity'].items():
                if count > 0:
                    color = severity_colors.get(level, Fore.WHITE)
                    print(f"   {color}{level.upper()}: {count}")
        
        # Ameaças detectadas
        if self.scan_results['threats_found']:
            print(f"\n{Fore.RED}🚨 AMEAÇAS DETECTADAS:")
            for i, threat in enumerate(self.scan_results['threats_found'], 1):
                print(f"\n   [{i}] {Path(threat['file']).name}")
                print(f"       Tipo: {threat['threat']}")
                print(f"       Severidade: {threat['severity'].upper()}")
                if 'size' in threat:
                    print(f"       Tamanho: {threat['size']/1024:.2f} KB")
                if threat.get('recommendations'):
                    print(f"       Ações: {', '.join(threat['recommendations'])}")
        
        # Taxa de detecção
        if self.scan_results['total_files'] > 0:
            detection_rate = (self.scan_results['infected_files'] + self.scan_results['suspicious_files']) / self.scan_results['total_files'] * 100
            print(f"\n{Fore.WHITE}📈 TAXA DE DETECÇÃO: {detection_rate:.1f}%")
        
        # Vantagens
        print(f"\n{Fore.GREEN}✅ VANTAGENS DO ANTIVÍRUS DISTRIBUÍDO:")
        print(f"   • Base de assinaturas sempre atualizada (tempo real)")
        print(f"   • Detecção de ameaças zero-day")
        print(f"   • Análise comportamental avançada")
        print(f"   • Inteligência coletiva de múltiplos clientes")
        print(f"   • Escalabilidade horizontal")
    
    def print_server_stats(self):
        """Imprime estatísticas do servidor"""
        try:
            response = requests.get(f'{self.server_url}/stats', timeout=5)
            if response.status_code == 200:
                stats = response.json()
                print(f"\n{Fore.CYAN}{'='*70}")
                print(f"{Fore.CYAN}ESTATÍSTICAS DO SERVIDOR")
                print(f"{Fore.CYAN}{'='*70}\n")
                print(f"Total de scans processados: {stats['total_scans']}")
                print(f"Ameaças detectadas (global): {stats['threats_detected']}")
                print(f"Clientes ativos: {stats['active_clients']}")
        except:
            pass

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python client.py <diretório ou arquivo>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if not os.path.exists(target):
        print(f"{Fore.RED}Erro: {target} não existe!")
        sys.exit(1)
    
    av = AntivirusDistribuidoCliente()
    av.scan_directory(target)

if __name__ == '__main__':
    main()
