import json
import os
from datetime import datetime
from dotenv import load_dotenv

# Cargar las variables de entorno desde la carpeta previa
load_dotenv(dotenv_path='../.env')

def read_data():
    """
    Lee los datos desde un archivo JSON o de texto, según la variable de entorno FILE_TYPE.
    """
    file_type = os.getenv('FILE_TYPE', 'json')
    data_path = f'../performance_log.{file_type}'
    
    try:
        print(f"Cargando datos desde {data_path}...")
        if file_type == 'json':
            with open(data_path, 'r') as file:
                data = json.load(file)
        else:
            with open(data_path, 'r') as file:
                content = file.read().strip()
                entries_text = content.split('---')
                data = []
                for entry_text in entries_text:
                    if not entry_text.strip():
                        continue
                    
                    entry_raw = {}
                    for line in entry_text.strip().split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            entry_raw[key.strip()] = value.strip()
                    
                    # Mapeo de claves del formato de texto al formato JSON
                    entry = {
                        'time': entry_raw.get('Time'),
                        'requestNumber': entry_raw.get('Request Number'),
                        'route': entry_raw.get('Route'),
                        'method': entry_raw.get('Method'),
                        'refTime': entry_raw.get('RefTime (Gas Computacional)'),
                        'proofSize': entry_raw.get('ProofSize'),
                        'tip': entry_raw.get('Tip'),
                        'duration': entry_raw.get('Duration'),
                        'groupID': entry_raw.get('GroupID'),
                        'cpuUsageStart': entry_raw.get('CPU Usage (start)'),
                        'cpuUsageEnd': entry_raw.get('CPU Usage (end)'),
                        'ramUsageStart': entry_raw.get('RAM Usage (start)'),
                        'ramUsageEnd': entry_raw.get('RAM Usage (end)'),
                        'transactionSuccess': entry_raw.get('Transaction Success'),
                        'parametersLength': entry_raw.get('Parameters Length'),
                        'testType': entry_raw.get('Test Type'),
                        'totalTransactions': entry_raw.get('Total Transactions'),
                    }
                    if any(entry.values()):
                        data.append(entry)

        print("Datos cargados exitosamente.")
        return data
    except FileNotFoundError:
        print(f"Error: El archivo '{data_path}' no fue encontrado.")
        return None
    except json.JSONDecodeError:
        print(f"Error: El archivo JSON '{data_path}' está mal formado.")
        return None
    except Exception as e:
        print(f"Ocurrió un error inesperado al leer los datos: {e}")
        return None

def calculate_transaction_cost(entry):
    """Calcula el costo de la transacción (gas)."""
    if entry.get('method') == 'GET':
        return 0.0
    
    ref_time_str = entry.get('refTime', '0')
    proof_size_str = entry.get('proofSize', '0')
    
    ref_time = float(ref_time_str) if ref_time_str and ref_time_str != 'N/A' else 0.0
    proof_size = float(proof_size_str) if proof_size_str and proof_size_str != 'N/A' else 0.0
    
    return ref_time + proof_size

def get_base_route(route):
    """Normaliza una ruta para agrupar endpoints similares."""
    if not isinstance(route, str):
        return 'Unknown'
    
    # Eliminar prefijos de método
    if route.startswith('GET '):
        route = route[len('GET '):]
    elif route.startswith('POST '):
        route = route[len('POST '):]
    
    # Agrupar rutas dinámicas
    if route.startswith('/role/'):
        return 'GET /role/'
    elif route.startswith('/has_permission/'):
        return 'GET /has_permission/'
    elif route.startswith('/create_user_with_dynamic_gas'):
        return 'POST /create_user_with_dynamic_gas'
    
    return route

def parse_data(data):
    """
    Analiza y transforma la lista de entradas de datos crudos a un formato limpio y estructurado.
    """
    if not data:
        return []

    parsed_data = []
    for entry in data:
        if not entry or all(value is None for value in entry.values()):
            continue

        try:
            # Solo procesar entradas exitosas o de tipo GET
            if entry.get('transactionSuccess') != 'Yes' and entry.get('method') != 'GET':
                continue

            # Validar que los campos numéricos y de fecha existan
            required_fields = ['time', 'duration', 'cpuUsageStart', 'cpuUsageEnd', 
                               'ramUsageStart', 'ramUsageEnd']
            if any(entry.get(field) is None for field in required_fields):
                continue

            duration = float(str(entry.get('duration', '0')).replace(' ms', ''))
            cpu_start = float(str(entry.get('cpuUsageStart', '0')).replace('%', ''))
            cpu_end = float(str(entry.get('cpuUsageEnd', '0')).replace('%', ''))
            ram_start = float(str(entry.get('ramUsageStart', '0')).replace('%', ''))
            ram_end = float(str(entry.get('ramUsageEnd', '0')).replace('%', ''))

            parsed_entry = {
                'timestamp': datetime.fromisoformat(entry['time'].replace('Z', '+00:00')),
                'route': get_base_route(entry.get('route', 'Unknown')),
                'method': entry.get('method', 'Unknown'),
                'duration': duration,
                'latency': duration,
                'cpuUsageDiff': cpu_end - cpu_start,
                'ramUsageDiff': ram_end - ram_start,
                'transactionCost': calculate_transaction_cost(entry),
                'refTime': float(entry.get('refTime', '0')) if entry.get('refTime') != 'N/A' else 0.0,
                'proofSize': float(entry.get('proofSize', '0')) if entry.get('proofSize') != 'N/A' else 0.0,
                'requestNumber': int(entry.get('requestNumber', 0)),
                'totalTransactions': int(entry.get('totalTransactions', 0)),
                'testType': str(entry.get('testType', 'Unknown')).strip().lower(),
                'parametersLength': int(entry.get('parametersLength', 0)),
                'groupID': entry.get('groupID', 'N/A'),
            }
            parsed_data.append(parsed_entry)

        except (ValueError, TypeError, KeyError) as e:
            print(f"Error procesando entrada, será omitida. Error: {e}. Entrada: {entry}")
            continue
    
    print(f"Se procesaron {len(parsed_data)} entradas de datos válidas.")
    return parsed_data
