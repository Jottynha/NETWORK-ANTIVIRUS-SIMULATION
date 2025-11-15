#!/usr/bin/env python3
"""
Antivírus Local - Demonstração
Escaneia arquivos usando uma base de assinaturas local
"""

import os
import hashlib
import json
import time
import psutil
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class AntivirusLocal:
    def __init__(self):
        self.signatures = {}
        self.load_signatures()
        self.scan_results = {
            'total_files': 0,
            'infected_files': 0,
            'clean_files': 0,
            'suspicious_files': 0,
            'scan_time': 0,
            'threats_found': [],
            'scan_speed': 0,  # arquivos por segundo
            'avg_time_per_file': 0,
            'total_bytes_scanned': 0,
            'detection_methods': {'hash': 0, 'pattern': 0, 'heuristic': 0},
            'threat_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'file_types_scanned': {},
            'largest_file': {'name': '', 'size': 0},
            'smallest_file': {'name': '', 'size': float('inf')}
        }
        self.scan_times = []  # tempos individuais de cada arquivo
        
    def load_signatures(self):
        """Carrega assinaturas de malware da base local"""
        signatures_file = Path(__file__).parent / 'signatures.db'
        
        if signatures_file.exists():
            with open(signatures_file, 'r') as f:
                self.signatures = json.load(f)
            print(f"{Fore.GREEN}✓ Base de assinaturas carregada: {len(self.signatures)} assinaturas")
            print(f"{Fore.YELLOW}⚠ Última atualização: {self.signatures.get('_last_update', 'Desconhecida')}")
        else:
            print(f"{Fore.RED}✗ Nenhuma base de assinaturas encontrada!")
            # Criar base básica
            self.create_default_signatures()
    
    def create_default_signatures(self):
        """Cria uma base de assinaturas padrão (desatualizada)"""
        self.signatures = {
            '_last_update': '2024-01-01',
            'malware': {
                # Hash MD5 de strings maliciosas simuladas
                'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2': 'Trojan.Generic.Old',
                'e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3': 'Virus.TestVirus.A',
                'f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4': 'Worm.EmailWorm.B',
            },
            'suspicious_patterns': [
                b'eval(',
                b'exec(',
                b'system(',
                b'__import__',
            ]
        }
        
        # Salvar
        signatures_file = Path(__file__).parent / 'signatures.db'
        with open(signatures_file, 'w') as f:
            json.dump(self.signatures, f, indent=2, default=str)
        
        print(f"{Fore.YELLOW}✓ Base de assinaturas padrão criada (DESATUALIZADA)")
    
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
    
    def scan_file(self, filepath):
        """Escaneia um arquivo individual com análise detalhada"""
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
        
        threat_detected = False
        detection_method = None
        severity = 'low'
        
        # Verificar hash
        file_hash = self.calculate_hash(filepath)
        if file_hash and file_hash in self.signatures.get('malware', {}):
            threat_name = self.signatures['malware'][file_hash]
            print(f"{Fore.RED}✗ AMEAÇA DETECTADA: {filepath}")
            print(f"  Tipo: {threat_name}")
            print(f"  Método: Assinatura Hash")
            print(f"  Severidade: CRÍTICA")
            self.scan_results['infected_files'] += 1
            self.scan_results['detection_methods']['hash'] += 1
            self.scan_results['threat_severity']['critical'] += 1
            self.scan_results['threats_found'].append({
                'file': str(filepath),
                'threat': threat_name,
                'hash': file_hash,
                'method': 'hash_signature',
                'severity': 'critical',
                'size': file_size
            })
            threat_detected = True
        
        # Verificar padrões suspeitos
        if not threat_detected:
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    for pattern in self.signatures.get('suspicious_patterns', []):
                        if pattern in content:
                            print(f"{Fore.YELLOW}⚠ SUSPEITO: {filepath}")
                            print(f"  Padrão encontrado: {pattern.decode('utf-8', errors='ignore')}")
                            print(f"  Método: Análise de Padrões")
                            print(f"  Severidade: MÉDIA")
                            self.scan_results['suspicious_files'] += 1
                            self.scan_results['detection_methods']['pattern'] += 1
                            self.scan_results['threat_severity']['medium'] += 1
                            self.scan_results['threats_found'].append({
                                'file': str(filepath),
                                'threat': 'Suspicious.Pattern',
                                'pattern': str(pattern),
                                'method': 'pattern_matching',
                                'severity': 'medium',
                                'size': file_size
                            })
                            threat_detected = True
                            break
            except:
                pass
        
        if not threat_detected:
            self.scan_results['clean_files'] += 1
            print(f"{Fore.GREEN}✓ Limpo: {filepath}")
        
        # Registrar tempo de scan
        file_scan_time = time.time() - file_start_time
        self.scan_times.append(file_scan_time)
        
        return threat_detected
    
    def scan_directory(self, directory):
        """Escaneia um diretório recursivamente"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}ANTIVÍRUS LOCAL - Iniciando Scan")
        print(f"{Fore.CYAN}{'='*70}\n")
        
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
        
        self.print_results()
    
    def print_results(self):
        """Imprime os resultados detalhados do scan"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}RESULTADO DO SCAN - ANTIVÍRUS LOCAL")
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
                print(f"       Método: {threat['method']}")
                print(f"       Severidade: {threat['severity'].upper()}")
                if 'size' in threat:
                    print(f"       Tamanho: {threat['size']/1024:.2f} KB")
        
        # Taxa de detecção
        if self.scan_results['total_files'] > 0:
            detection_rate = (self.scan_results['infected_files'] + self.scan_results['suspicious_files']) / self.scan_results['total_files'] * 100
            print(f"\n{Fore.WHITE}📈 TAXA DE DETECÇÃO: {detection_rate:.1f}%")
        
        # Limitações
        print(f"\n{Fore.YELLOW}⚠️  LIMITAÇÕES DO ANTIVÍRUS LOCAL:")
        print(f"   • Base de assinaturas desatualizada ({self.signatures.get('_last_update', 'desconhecida')})")
        print(f"   • {len(self.signatures.get('malware', {}))} assinaturas conhecidas (limitado)")
        print(f"   • Não detecta ameaças zero-day")
        print(f"   • Análise estática apenas")
        print(f"   • Sem inteligência coletiva")

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python antivirus_local.py <diretório ou arquivo>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if not os.path.exists(target):
        print(f"{Fore.RED}Erro: {target} não existe!")
        sys.exit(1)
    
    av = AntivirusLocal()
    av.scan_directory(target)

if __name__ == '__main__':
    main()
