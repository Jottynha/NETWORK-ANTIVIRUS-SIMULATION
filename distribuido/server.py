# Servidor do Antivírus Distribuído/Mantém base de assinaturas atualizada e processa requisições de clientes


from flask import Flask, request, jsonify
import hashlib
import json
import time
from datetime import datetime
from colorama import Fore, Style, init
from pathlib import Path

init(autoreset=True)

app = Flask(__name__)

class SignaturesDB:
    def __init__(self):
        self.db_file = Path(__file__).parent / 'signatures_db.json'
        self.load_database()
        self.stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'clients_connected': set()
        }
    
    def load_database(self):
        """Carrega a base de assinaturas"""
        if self.db_file.exists():
            with open(self.db_file, 'r') as f:
                self.database = json.load(f)
        else:
            self.create_updated_database()
    
    def create_updated_database(self):
        """Cria uma base de assinaturas atualizada"""
        self.database = {
            '_last_update': datetime.now().isoformat(),
            '_version': '2.5',
            'malware': {
                # Mesmas assinaturas antigas
                'd41d8cd98f00b204e9800998ecf8427e': 'Empty.File.Test',
                '5d41402abc4b2a76b9719d911017c592': 'Test.Malware.Hello',
                '7d793037a0760186574b0282f2f435e7': 'Trojan.WorldVirus',
                '098f6bcd4621d373cade4e832627b4f6': 'Generic.Malware.Test',
                
                # Novas assinaturas (zero-day)
                '5eb63bbbe01eeed093cb22bb8f5acdc3': 'Trojan.Ransomware.2024',
                '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae': 'Worm.CryptoMiner.New',
                'ad57366865126e55649ecb23ae1d48887544976efea46a48eb5d85a6eeb4d306': 'Virus.ZeroDay.Critical',
            },
            'suspicious_patterns': [
                'eval(',
                'exec(',
                'system(',
                '__import__',
                'os.system',
                'subprocess.call',
                'base64.b64decode',
                'socket.connect',
                'requests.post'
            ],
            'behavioral_rules': [
                {
                    'name': 'Multiple File Access',
                    'description': 'Acesso rápido a múltiplos arquivos',
                    'severity': 'high'
                },
                {
                    'name': 'Network Connection',
                    'description': 'Tentativa de conexão externa',
                    'severity': 'medium'
                }
            ]
        }
        
        with open(self.db_file, 'w') as f:
            json.dump(self.database, f, indent=2)
        
        print(f"{Fore.GREEN}Base de assinaturas atualizada criada")

# Instância global
signatures_db = SignaturesDB()

@app.route('/health', methods=['GET'])
def health():
    """Endpoint de saúde"""
    return jsonify({
        'status': 'online',
        'version': signatures_db.database.get('_version', '1.0'),
        'last_update': signatures_db.database.get('_last_update'),
        'total_signatures': len(signatures_db.database.get('malware', {}))
    })

@app.route('/signatures', methods=['GET'])
def get_signatures():
    """Retorna a base de assinaturas completa"""
    client_id = request.args.get('client_id', 'unknown')
    signatures_db.stats['clients_connected'].add(client_id)
    
    print(f"{Fore.CYAN}Cliente {client_id} solicitou assinaturas")
    
    return jsonify(signatures_db.database)

@app.route('/scan', methods=['POST'])
def scan_file():
    """Endpoint para scan de arquivo"""
    data = request.json
    file_hash = data.get('hash')
    file_name = data.get('name', 'unknown')
    client_id = data.get('client_id', 'unknown')
    content_preview = data.get('content_preview', '')
    
    signatures_db.stats['total_scans'] += 1
    signatures_db.stats['clients_connected'].add(client_id)
    
    result = {
        'clean': True,
        'threat': None,
        'severity': 'none',
        'recommendations': []
    }
    
    # Verificar hash
    if file_hash in signatures_db.database.get('malware', {}):
        threat_name = signatures_db.database['malware'][file_hash]
        result['clean'] = False
        result['threat'] = threat_name
        result['severity'] = 'critical'
        result['recommendations'].append('Deletar arquivo imediatamente')
        signatures_db.stats['threats_detected'] += 1
        
        print(f"{Fore.RED}AMEAÇA DETECTADA: {file_name}")
        print(f"   Cliente: {client_id}")
        print(f"   Tipo: {threat_name}")
    
    # Verificar padrões suspeitos
    elif content_preview:
        for pattern in signatures_db.database.get('suspicious_patterns', []):
            if pattern in content_preview:
                result['clean'] = False
                result['threat'] = 'Suspicious.Pattern'
                result['severity'] = 'medium'
                result['recommendations'].append(f'Padrão suspeito encontrado: {pattern}')
                signatures_db.stats['threats_detected'] += 1
                
                print(f"{Fore.YELLOW}⚠ SUSPEITO: {file_name}")
                print(f"   Cliente: {client_id}")
                print(f"   Padrão: {pattern}")
    
    if result['clean']:
        print(f"{Fore.GREEN}Limpo: {file_name} (Cliente: {client_id})")
    
    return jsonify(result)

@app.route('/stats', methods=['GET'])
def get_stats():
    """Retorna estatísticas do servidor"""
    return jsonify({
        'total_scans': signatures_db.stats['total_scans'],
        'threats_detected': signatures_db.stats['threats_detected'],
        'active_clients': len(signatures_db.stats['clients_connected']),
        'clients': list(signatures_db.stats['clients_connected'])
    })

@app.route('/update', methods=['POST'])
def update_signature():
    """Endpoint para adicionar novas assinaturas (simulação de atualização automática)"""
    data = request.json
    file_hash = data.get('hash')
    threat_name = data.get('threat_name')
    
    if file_hash and threat_name:
        signatures_db.database['malware'][file_hash] = threat_name
        signatures_db.database['_last_update'] = datetime.now().isoformat()
        
        # Salvar
        with open(signatures_db.db_file, 'w') as f:
            json.dump(signatures_db.database, f, indent=2)
        
        print(f"{Fore.GREEN}✓ Nova assinatura adicionada: {threat_name}")
        return jsonify({'success': True, 'message': 'Assinatura adicionada'})
    
    return jsonify({'success': False, 'message': 'Dados inválidos'}), 400

def main():
    print(f"{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}SERVIDOR ANTIVÍRUS DISTRIBUÍDO")
    print(f"{Fore.CYAN}{'='*70}\n")
    print(f"{Fore.GREEN}Servidor iniciado em http://localhost:5000")
    print(f"{Fore.GREEN}Base de assinaturas: {len(signatures_db.database.get('malware', {}))} assinaturas")
    print(f"{Fore.GREEN}Última atualização: {signatures_db.database.get('_last_update')}\n")
    print(f"{Fore.YELLOW}Aguardando conexões de clientes...\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    main()
