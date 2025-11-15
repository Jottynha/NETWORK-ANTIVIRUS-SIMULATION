# Análise Comparativa Completa - Antivírus Local vs Distribuído
import subprocess
import sys
from colorama import Fore, init

init(autoreset=True)
print(f"{Fore.CYAN}{'='*70}")
print(f"{Fore.CYAN}ANÁLISE COMPARATIVA: ANTIVÍRUS LOCAL vs DISTRIBUÍDO")
print(f"{Fore.CYAN}{'='*70}\n")
print(f"{Fore.YELLOW}Executando testes...\n")

# Teste 1: Local
print(f"{Fore.CYAN}[1/2] Antivírus Local...")
result_local = subprocess.run(
    [sys.executable, 'local/antivirus_local.py', 'test_files/'],
    capture_output=True, text=True
)
print(result_local.stdout)

# Teste 2: Distribuído
print(f"\n{Fore.CYAN}[2/2] Antivírus Distribuído...")
result_dist = subprocess.run(
    [sys.executable, 'distribuido/client.py', 'test_files/'],
    capture_output=True, text=True
)
print(result_dist.stdout)

# Comparação
print(f"\n{Fore.GREEN}{'='*70}")
print(f"{Fore.GREEN}COMPARAÇÃO CONCLUÍDA!")
print(f"{Fore.GREEN}{'='*70}\n")
