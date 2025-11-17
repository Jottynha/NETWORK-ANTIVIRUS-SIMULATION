#!/usr/bin/env python3
"""
Análise Comparativa Completa com Gráficos - Antivírus Local vs Distribuído
Executa testes, coleta métricas e gera visualizações comparativas
"""

import subprocess
import sys
import re
from pathlib import Path
from colorama import Fore, init
from tabulate import tabulate
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Backend sem GUI
import numpy as np
from datetime import datetime

init(autoreset=True)

class AnalisadorComparativoComGraficos:
    def __init__(self):
        self.results = {
            'local': {'metrics': {}, 'raw_output': ''},
            'distribuido': {'metrics': {}, 'raw_output': ''}
        }
        self.graficos_dir = Path('graficos_comparativos')
        self.graficos_dir.mkdir(exist_ok=True)
    
    def executar_teste_local(self):
        """Executa teste com antivírus local"""
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}[1/2] Executando Antivírus Local...")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        try:
            result = subprocess.run(
                [sys.executable, 'local/antivirus_local.py', 'test_files/'],
                capture_output=True, text=True, timeout=30
            )
            
            self.results['local']['raw_output'] = result.stdout
            self.results['local']['success'] = result.returncode == 0
            
            print(result.stdout)
            self.extrair_metricas('local', result.stdout)
            
        except Exception as e:
            print(f"{Fore.RED}Erro: {e}")
            self.results['local']['success'] = False
    
    def executar_teste_distribuido(self):
        """Executa teste com antivírus distribuído"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}[2/2] Executando Antivírus Distribuído...")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        # Verificar servidor
        import requests
        try:
            requests.get('http://localhost:5000/health', timeout=2)
        except:
            print(f"{Fore.RED}✗ Servidor não está rodando!")
            print(f"{Fore.YELLOW}Execute: python3 distribuido/server.py\n")
            self.results['distribuido']['success'] = False
            return
        
        try:
            result = subprocess.run(
                [sys.executable, 'distribuido/client.py', 'test_files/'],
                capture_output=True, text=True, timeout=30
            )
            
            self.results['distribuido']['raw_output'] = result.stdout
            self.results['distribuido']['success'] = result.returncode == 0
            
            print(result.stdout)
            self.extrair_metricas('distribuido', result.stdout)
            
        except Exception as e:
            print(f"{Fore.RED}Erro: {e}")
            self.results['distribuido']['success'] = False
    
    def extrair_metricas(self, tipo, output):
        """Extrai métricas do output usando regex"""
        patterns = {
            'total_files': r'Total de arquivos escaneados:\s*(\d+)',
            'clean_files': r'Arquivos limpos:\s*(\d+)',
            'infected_files': r'Arquivos infectados:\s*(\d+)',
            'suspicious_files': r'Arquivos suspeitos:\s*(\d+)',
            'scan_time': r'Tempo total de scan:\s*([\d.]+)s',
            'scan_speed': r'Velocidade:\s*([\d.]+)\s*arquivos/segundo',
            'avg_time_per_file': r'Tempo médio por arquivo:\s*([\d.]+)ms',
            'memory_used': r'Memória utilizada:\s*([\d.]+)\s*MB',
            'total_data': r'Total de dados escaneados:\s*([\d.]+)\s*MB',
            'throughput': r'Taxa de transferência:\s*([\d.]+)\s*MB/s',
            'detection_rate': r'TAXA DE DETECÇÃO:\s*([\d.]+)%',
        }
        
        # Métricas específicas do distribuído
        if tipo == 'distribuido':
            patterns.update({
                'network_requests': r'Requisições ao servidor:\s*(\d+)',
                'data_sent': r'Dados enviados:\s*([\d.]+)\s*KB',
                'data_received': r'Dados recebidos:\s*([\d.]+)\s*KB',
                'avg_latency': r'Latência média:\s*([\d.]+)ms',
            })
        
        metrics = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                metrics[key] = float(match.group(1))
        
        self.results[tipo]['metrics'] = metrics
    
    def gerar_grafico_performance(self):
        """Gera gráfico comparativo de performance"""
        print(f"\n{Fore.CYAN}📊 Gerando gráfico de performance...")
        
        local = self.results['local']['metrics']
        dist = self.results['distribuido']['metrics']
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Análise de Performance: Local vs Distribuído', fontsize=16, fontweight='bold')
        
        # 1. Tempo de Scan
        ax1 = axes[0, 0]
        tipos = ['Local', 'Distribuído']
        tempos = [local.get('scan_time', 0), dist.get('scan_time', 0)]
        colors = ['#2ecc71', '#3498db']
        bars1 = ax1.bar(tipos, tempos, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax1.set_ylabel('Tempo (segundos)', fontweight='bold')
        ax1.set_title('Tempo Total de Scan', fontweight='bold')
        ax1.grid(axis='y', alpha=0.3, linestyle='--')
        
        # Adicionar valores nas barras
        for bar, tempo in zip(bars1, tempos):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{tempo:.3f}s', ha='center', va='bottom', fontweight='bold')
        
        # 2. Velocidade (arquivos/segundo)
        ax2 = axes[0, 1]
        velocidades = [local.get('scan_speed', 0), dist.get('scan_speed', 0)]
        bars2 = ax2.bar(tipos, velocidades, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax2.set_ylabel('Arquivos/segundo', fontweight='bold')
        ax2.set_title('Velocidade de Processamento', fontweight='bold')
        ax2.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bar, vel in zip(bars2, velocidades):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{vel:.2f}', ha='center', va='bottom', fontweight='bold')
        
        # 3. Tempo médio por arquivo
        ax3 = axes[1, 0]
        tempo_medio = [local.get('avg_time_per_file', 0), dist.get('avg_time_per_file', 0)]
        bars3 = ax3.bar(tipos, tempo_medio, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax3.set_ylabel('Tempo (milissegundos)', fontweight='bold')
        ax3.set_title('Tempo Médio por Arquivo', fontweight='bold')
        ax3.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bar, tempo in zip(bars3, tempo_medio):
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{tempo:.2f}ms', ha='center', va='bottom', fontweight='bold')
        
        # 4. Throughput (MB/s)
        ax4 = axes[1, 1]
        throughput = [local.get('throughput', 0), dist.get('throughput', 0)]
        bars4 = ax4.bar(tipos, throughput, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax4.set_ylabel('MB/segundo', fontweight='bold')
        ax4.set_title('Taxa de Transferência', fontweight='bold')
        ax4.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bar, tp in zip(bars4, throughput):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height,
                    f'{tp:.2f}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        filename = self.graficos_dir / 'performance_comparison.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"{Fore.GREEN}✓ Salvo: {filename}")
    
    def gerar_grafico_recursos(self):
        """Gera gráfico de uso de recursos"""
        print(f"{Fore.CYAN}📊 Gerando gráfico de recursos...")
        
        local = self.results['local']['metrics']
        dist = self.results['distribuido']['metrics']
        
        fig, axes = plt.subplots(1, 3, figsize=(16, 5))
        fig.suptitle('Uso de Recursos: Local vs Distribuído', fontsize=16, fontweight='bold')
        
        # 1. Memória RAM
        ax1 = axes[0]
        memoria = [local.get('memory_used', 0), dist.get('memory_used', 0)]
        colors = ['#2ecc71', '#3498db']
        bars1 = ax1.bar(['Local', 'Distribuído'], memoria, color=colors, alpha=0.8, 
                       edgecolor='black', linewidth=1.5)
        ax1.set_ylabel('Memória (MB)', fontweight='bold')
        ax1.set_title('Uso de Memória RAM', fontweight='bold')
        ax1.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bar, mem in zip(bars1, memoria):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{mem:.2f} MB', ha='center', va='bottom', fontweight='bold')
        
        # 2. Dados Processados
        ax2 = axes[1]
        dados = [local.get('total_data', 0), dist.get('total_data', 0)]
        bars2 = ax2.bar(['Local', 'Distribuído'], dados, color=colors, alpha=0.8,
                       edgecolor='black', linewidth=1.5)
        ax2.set_ylabel('Dados (MB)', fontweight='bold')
        ax2.set_title('Total de Dados Escaneados', fontweight='bold')
        ax2.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bar, dado in zip(bars2, dados):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{dado:.2f} MB', ha='center', va='bottom', fontweight='bold')
        
        # 3. Uso de Rede (apenas distribuído)
        ax3 = axes[2]
        rede_dados = [0, dist.get('data_sent', 0) + dist.get('data_received', 0)]
        bars3 = ax3.bar(['Local\n(Offline)', 'Distribuído\n(Online)'], rede_dados, 
                       color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax3.set_ylabel('Tráfego de Rede (KB)', fontweight='bold')
        ax3.set_title('Uso de Rede', fontweight='bold')
        ax3.grid(axis='y', alpha=0.3, linestyle='--')
        
        for bar, rede in zip(bars3, rede_dados):
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{rede:.2f} KB' if rede > 0 else '0 KB',
                    ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        filename = self.graficos_dir / 'recursos_comparison.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"{Fore.GREEN}✓ Salvo: {filename}")
    
    def gerar_grafico_deteccao(self):
        """Gera gráfico de eficácia de detecção"""
        print(f"{Fore.CYAN}📊 Gerando gráfico de detecção...")
        
        local = self.results['local']['metrics']
        dist = self.results['distribuido']['metrics']
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Eficácia de Detecção: Local vs Distribuído', fontsize=16, fontweight='bold')
        
        # 1. Arquivos por Status
        ax1 = axes[0]
        categorias = ['Limpos', 'Infectados', 'Suspeitos']
        local_counts = [
            local.get('clean_files', 0),
            local.get('infected_files', 0),
            local.get('suspicious_files', 0)
        ]
        dist_counts = [
            dist.get('clean_files', 0),
            dist.get('infected_files', 0),
            dist.get('suspicious_files', 0)
        ]
        
        x = np.arange(len(categorias))
        width = 0.35
        
        bars1 = ax1.bar(x - width/2, local_counts, width, label='Local', 
                       color='#2ecc71', alpha=0.8, edgecolor='black', linewidth=1.5)
        bars2 = ax1.bar(x + width/2, dist_counts, width, label='Distribuído',
                       color='#3498db', alpha=0.8, edgecolor='black', linewidth=1.5)
        
        ax1.set_ylabel('Número de Arquivos', fontweight='bold')
        ax1.set_title('Distribuição de Arquivos por Status', fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(categorias)
        ax1.legend()
        ax1.grid(axis='y', alpha=0.3, linestyle='--')
        
        # Adicionar valores
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax1.text(bar.get_x() + bar.get_width()/2., height,
                            f'{int(height)}', ha='center', va='bottom', fontweight='bold')
        
        # 2. Taxa de Detecção
        ax2 = axes[1]
        detection_rates = [local.get('detection_rate', 0), dist.get('detection_rate', 0)]
        colors = ['#2ecc71', '#3498db']
        bars = ax2.bar(['Local', 'Distribuído'], detection_rates, color=colors, 
                      alpha=0.8, edgecolor='black', linewidth=1.5)
        ax2.set_ylabel('Taxa de Detecção (%)', fontweight='bold')
        ax2.set_title('Taxa de Detecção de Ameaças', fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.grid(axis='y', alpha=0.3, linestyle='--')
        
        # Linha de referência em 100%
        ax2.axhline(y=100, color='red', linestyle='--', alpha=0.5, label='100% (Ideal)')
        ax2.legend()
        
        for bar, rate in zip(bars, detection_rates):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{rate:.1f}%', ha='center', va='bottom', fontweight='bold', fontsize=12)
        
        plt.tight_layout()
        filename = self.graficos_dir / 'deteccao_comparison.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"{Fore.GREEN}✓ Salvo: {filename}")
    
    def gerar_grafico_radar(self):
        """Gera gráfico radar comparativo"""
        print(f"{Fore.CYAN}📊 Gerando gráfico radar...")
        
        local = self.results['local']['metrics']
        dist = self.results['distribuido']['metrics']
        
        # Normalizar métricas para 0-100
        categorias = ['Velocidade', 'Detecção', 'Eficiência\nMemória', 
                     'Throughput', 'Confiabilidade']
        
        # Calcular scores normalizados
        velocidade_local = min(100, (local.get('scan_speed', 0) / max(local.get('scan_speed', 1), dist.get('scan_speed', 1))) * 100)
        velocidade_dist = min(100, (dist.get('scan_speed', 0) / max(local.get('scan_speed', 1), dist.get('scan_speed', 1))) * 100)
        
        deteccao_local = local.get('detection_rate', 0)
        deteccao_dist = dist.get('detection_rate', 0)
        
        mem_max = max(local.get('memory_used', 1), dist.get('memory_used', 1))
        efic_mem_local = 100 - (local.get('memory_used', 0) / mem_max * 100) if mem_max > 0 else 0
        efic_mem_dist = 100 - (dist.get('memory_used', 0) / mem_max * 100) if mem_max > 0 else 0
        
        throughput_max = max(local.get('throughput', 1), dist.get('throughput', 1))
        throughput_local = (local.get('throughput', 0) / throughput_max * 100) if throughput_max > 0 else 0
        throughput_dist = (dist.get('throughput', 0) / throughput_max * 100) if throughput_max > 0 else 0
        
        # Confiabilidade baseada em múltiplos fatores
        conf_local = (velocidade_local + deteccao_local + efic_mem_local) / 3
        conf_dist = (velocidade_dist + deteccao_dist + throughput_dist) / 3
        
        valores_local = [velocidade_local, deteccao_local, efic_mem_local, throughput_local, conf_local]
        valores_dist = [velocidade_dist, deteccao_dist, efic_mem_dist, throughput_dist, conf_dist]
        
        # Número de variáveis
        N = len(categorias)
        angulos = [n / float(N) * 2 * np.pi for n in range(N)]
        valores_local += valores_local[:1]
        valores_dist += valores_dist[:1]
        angulos += angulos[:1]
        
        fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
        
        ax.plot(angulos, valores_local, 'o-', linewidth=2, label='Local', color='#2ecc71')
        ax.fill(angulos, valores_local, alpha=0.25, color='#2ecc71')
        
        ax.plot(angulos, valores_dist, 'o-', linewidth=2, label='Distribuído', color='#3498db')
        ax.fill(angulos, valores_dist, alpha=0.25, color='#3498db')
        
        ax.set_xticks(angulos[:-1])
        ax.set_xticklabels(categorias, size=11, fontweight='bold')
        ax.set_ylim(0, 100)
        ax.set_yticks([20, 40, 60, 80, 100])
        ax.set_yticklabels(['20', '40', '60', '80', '100'], size=9)
        ax.grid(True, linestyle='--', alpha=0.7)
        
        plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=11)
        plt.title('Análise Multidimensional: Local vs Distribuído', 
                 size=14, fontweight='bold', pad=20)
        
        filename = self.graficos_dir / 'radar_comparison.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"{Fore.GREEN}✓ Salvo: {filename}")
    
    def gerar_grafico_pizza(self):
        """Gera gráficos de pizza para visualização de proporções"""
        print(f"{Fore.CYAN}📊 Gerando gráficos de pizza...")
        
        local = self.results['local']['metrics']
        dist = self.results['distribuido']['metrics']
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Proporção de Arquivos por Status', fontsize=16, fontweight='bold')
        
        # Local
        ax1 = axes[0]
        sizes_local = [
            local.get('clean_files', 0),
            local.get('infected_files', 0),
            local.get('suspicious_files', 0)
        ]
        labels = ['Limpos', 'Infectados', 'Suspeitos']
        colors = ['#2ecc71', '#e74c3c', '#f39c12']
        explode = (0.05, 0.05, 0.05)
        
        if sum(sizes_local) > 0:
            wedges, texts, autotexts = ax1.pie(sizes_local, explode=explode, labels=labels,
                                               colors=colors, autopct='%1.1f%%',
                                               shadow=True, startangle=90)
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(11)
        
        ax1.set_title('Antivírus Local', fontweight='bold', fontsize=12)
        
        # Distribuído
        ax2 = axes[1]
        sizes_dist = [
            dist.get('clean_files', 0),
            dist.get('infected_files', 0),
            dist.get('suspicious_files', 0)
        ]
        
        if sum(sizes_dist) > 0:
            wedges, texts, autotexts = ax2.pie(sizes_dist, explode=explode, labels=labels,
                                               colors=colors, autopct='%1.1f%%',
                                               shadow=True, startangle=90)
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(11)
        
        ax2.set_title('Antivírus Distribuído', fontweight='bold', fontsize=12)
        
        plt.tight_layout()
        filename = self.graficos_dir / 'pizza_comparison.png'
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"{Fore.GREEN}✓ Salvo: {filename}")
    
    def gerar_tabela_comparativa(self):
        """Gera tabela textual comparativa"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}TABELA COMPARATIVA")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        local = self.results['local']['metrics']
        dist = self.results['distribuido']['metrics']
        
        dados = [
            ['MÉTRICA', 'LOCAL', 'DISTRIBUÍDO', 'DIFERENÇA']
        ]
        
        metricas = [
            ('Tempo Total', 'scan_time', 's', lambda x: f"{x:.3f}"),
            ('Velocidade', 'scan_speed', 'arq/s', lambda x: f"{x:.2f}"),
            ('Tempo/Arquivo', 'avg_time_per_file', 'ms', lambda x: f"{x:.2f}"),
            ('Memória', 'memory_used', 'MB', lambda x: f"{x:.2f}"),
            ('Throughput', 'throughput', 'MB/s', lambda x: f"{x:.2f}"),
            ('Taxa Detecção', 'detection_rate', '%', lambda x: f"{x:.1f}"),
        ]
        
        for nome, key, unidade, fmt in metricas:
            val_local = local.get(key, 0)
            val_dist = dist.get(key, 0)
            
            if val_local > 0:
                diff = ((val_dist - val_local) / val_local * 100)
                diff_str = f"{diff:+.1f}%"
            else:
                diff_str = "N/A"
            
            dados.append([
                nome,
                f"{fmt(val_local)} {unidade}",
                f"{fmt(val_dist)} {unidade}",
                diff_str
            ])
        
        print(tabulate(dados, headers='firstrow', tablefmt='grid'))
    
    def gerar_relatorio_final(self):
        """Gera relatório final em texto"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}RELATÓRIO FINAL")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        relatorio_path = self.graficos_dir / 'relatorio_completo.txt'
        
        with open(relatorio_path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("RELATÓRIO COMPARATIVO: ANTIVÍRUS LOCAL vs DISTRIBUÍDO\n")
            f.write("="*70 + "\n\n")
            f.write(f"Data/Hora: {timestamp}\n\n")
            
            f.write("MÉTRICAS COLETADAS:\n")
            f.write("-"*70 + "\n\n")
            
            local = self.results['local']['metrics']
            dist = self.results['distribuido']['metrics']
            
            f.write("ANTIVÍRUS LOCAL:\n")
            for key, value in sorted(local.items()):
                f.write(f"  {key}: {value}\n")
            
            f.write("\nANTIVÍRUS DISTRIBUÍDO:\n")
            for key, value in sorted(dist.items()):
                f.write(f"  {key}: {value}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("CONCLUSÕES:\n")
            f.write("="*70 + "\n\n")
            
            # Análises
            if dist.get('detection_rate', 0) > local.get('detection_rate', 0):
                diff = dist['detection_rate'] - local['detection_rate']
                f.write(f"✓ Distribuído detecta {diff:.1f}% a mais de ameaças\n")
            
            if local.get('scan_time', float('inf')) < dist.get('scan_time', float('inf')):
                f.write(f"✓ Local é mais rápido em scans pequenos\n")
            
            if 'avg_latency' in dist:
                f.write(f"⚠ Latência de rede adiciona ~{dist['avg_latency']:.1f}ms por arquivo\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("GRÁFICOS GERADOS:\n")
            f.write("="*70 + "\n\n")
            f.write("  • performance_comparison.png - Análise de Performance\n")
            f.write("  • recursos_comparison.png - Uso de Recursos\n")
            f.write("  • deteccao_comparison.png - Eficácia de Detecção\n")
            f.write("  • radar_comparison.png - Análise Multidimensional\n")
            f.write("  • pizza_comparison.png - Proporções de Status\n")
        
        print(f"{Fore.GREEN}✓ Relatório salvo: {relatorio_path}")

def main():
    print(f"{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}ANÁLISE COMPARATIVA COM GRÁFICOS")
    print(f"{Fore.CYAN}Antivírus Local vs Distribuído")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    analisador = AnalisadorComparativoComGraficos()
    
    # Executar testes
    analisador.executar_teste_local()
    analisador.executar_teste_distribuido()
    
    if not analisador.results['distribuido']['success']:
        print(f"\n{Fore.RED}✗ Não foi possível completar análise distribuída")
        print(f"{Fore.YELLOW}Certifique-se de que o servidor está rodando!")
        return
    
    # Gerar tabela
    analisador.gerar_tabela_comparativa()
    
    # Gerar gráficos
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}GERANDO VISUALIZAÇÕES GRÁFICAS")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    analisador.gerar_grafico_performance()
    analisador.gerar_grafico_recursos()
    analisador.gerar_grafico_deteccao()
    analisador.gerar_grafico_radar()
    analisador.gerar_grafico_pizza()
    analisador.gerar_relatorio_final()
    
    print(f"\n{Fore.GREEN}{'='*70}")
    print(f"{Fore.GREEN}✓ ANÁLISE COMPLETA FINALIZADA!")
    print(f"{Fore.GREEN}{'='*70}\n")
    print(f"{Fore.WHITE}📁 Gráficos salvos em: {Fore.CYAN}graficos_comparativos/")
    print(f"{Fore.WHITE}📄 Relatório completo: {Fore.CYAN}graficos_comparativos/relatorio_completo.txt\n")

if __name__ == '__main__':
    main()
