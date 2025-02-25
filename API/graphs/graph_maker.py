import json
import matplotlib.pyplot as plt
import os
from statistics import mean, median
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from collections import Counter
import re  # Importar el módulo re para expresiones regulares
import time
# Cargar las variables de entorno desde la carpeta previa
load_dotenv(dotenv_path='../.env')

def read_data():
    # Verifica la variable de entorno para determinar el archivo a leer
    file_type = os.getenv('FILE_TYPE', 'json')  # Establece 'json' como predeterminado si no se especifica

    if file_type == 'json':
        with open('../performance_log.json', 'r') as file:
            data = json.load(file)
    else:
        with open('../performance_log.txt', 'r') as file:
            content = file.read().strip()
            entries = content.split('---')
            data = []
            for entry_text in entries:
                entry_raw = {}
                lines = entry_text.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        # Manejar líneas con formato 'Clave: Valor'
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            entry_raw[key] = value
                # Mapeo de claves originales a estandarizadas
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
        print("Datos cargados exitosamente")
        return data

def calculate_transaction_cost(entry):
    if entry.get('method') == 'GET':
        return 0.0
    refTime = entry.get('refTime', '0')
    proofSize = entry.get('proofSize', '0')
    refTime = float(refTime) if refTime != 'N/A' else 0.0
    proofSize = float(proofSize) if proofSize != 'N/A' else 0.0
    return refTime + proofSize

def get_base_route(route):
    # Eliminar los prefijos 'GET ' y 'POST ' si están presentes
    if route.startswith('GET '):
        route = route[len('GET '):]
    elif route.startswith('POST '):
        route = route[len('POST '):]
    # Reemplazar segmentos variables por placeholders
    if route.startswith('/role/'):
        return 'GET /role/'  # Rutas genéricas para /role/
    elif route.startswith('/has_permission/'):
        return 'GET /has_permission/'  # Rutas genéricas para /has_permission/
    elif route.startswith('/create_user_with_dynamic_gas'):
        return 'POST /create_user_with_dynamic_gas'
    # Agregar más patrones según tus endpoints
    else:
        print(f"Ruta no reconocida: {route}")
        return route

def parse_data(data):
    parsed_data = []
    null_entries = 0

    for entry in data:
        # Ignorar entradas completamente nulas
        if all(value is None for value in entry.values()):
            null_entries += 1
            continue

        try:
            # Procesar entradas con 'transactionSuccess' == 'Yes' o método 'GET'
            if entry.get('transactionSuccess') == 'Yes' or entry.get('method') == 'GET':
                # Validar que los campos requeridos existan y no sean None
                required_fields = ['time', 'duration', 'cpuUsageStart', 'cpuUsageEnd',
                                   'ramUsageStart', 'ramUsageEnd', 'testType', 'method',
                                   'groupID', 'requestNumber', 'totalTransactions']
                missing_fields = [field for field in required_fields if not entry.get(field)]
                if missing_fields:
                    print(f"Entrada omitida por campos faltantes {missing_fields}: {entry}")
                    continue

                # Convertir valores numéricos de manera segura
                duration = float(entry.get('duration', '0').replace(' ms', ''))
                cpu_start = float(entry.get('cpuUsageStart', '0').replace('%', ''))
                cpu_end = float(entry.get('cpuUsageEnd', '0').replace('%', ''))
                ram_start = float(entry.get('ramUsageStart', '0').replace('%', ''))
                ram_end = float(entry.get('ramUsageEnd', '0').replace('%', ''))
                
                # Obtener la ruta genérica
                route = entry.get('route', 'Unknown')
                
                base_route = get_base_route(route)

                # Normalizar el campo testType
                test_type = entry.get('testType', 'Unknown')
                if isinstance(test_type, str):
                    test_type = test_type.strip().lower()
                else:
                    test_type = str(test_type)

                parsed_entry = {
                    'duration': duration,
                    'cpuUsageStart': cpu_start,
                    'cpuUsageEnd': cpu_end,
                    'ramUsageStart': ram_start,
                    'ramUsageEnd': ram_end,
                    'cpuUsageDiff': cpu_end - cpu_start,
                    'ramUsageDiff': ram_end - ram_start,
                    'transactionCost': calculate_transaction_cost(entry),
                    'latency': duration,
                    'timestamp': datetime.fromisoformat(entry['time'].replace('Z', '+00:00')),
                    'groupID': entry.get('groupID', 'N/A'),
                    'requestNumber': int(entry.get('requestNumber', 0)) if entry.get('requestNumber', 'N/A') != 'N/A' else 0,
                    'totalTransactions': int(entry.get('totalTransactions', 0)) if entry.get('totalTransactions', 'N/A') != 'N/A' else 0,
                    'testType': test_type,  # Actualizado para usar test_type normalizado
                    'parametersLength': int(entry.get('parametersLength', 0)) if entry.get('parametersLength', 'N/A') != 'N/A' else 0,
                    'method': entry.get('method', 'Unknown'),
                    'route': base_route,  # Asegurarse de que la ruta es limpia y consistente
                    'refTime': float(entry.get('refTime', '0')) if entry.get('refTime') != 'N/A' else 0.0,
                    'proofSize': float(entry.get('proofSize', '0')) if entry.get('proofSize') != 'N/A' else 0.0,
                }
                parsed_data.append(parsed_entry)
            else:
                print(f"Entrada omitida (transactionSuccess != Yes y método no es GET): {entry}")
        except Exception as e:
            print(f"Error procesando entrada: {entry}")
            print(f"Error detallado: {str(e)}")
            continue

    if null_entries > 0:
        print(f"Se encontraron {null_entries} entradas nulas que fueron ignoradas")
    if not parsed_data:
        print("Advertencia: No se pudo procesar ningún dato válido")
    else:
        print(f"Se procesaron {len(parsed_data)} entradas de datos")
        print(f"Primera entrada procesada: {parsed_data[0]}")

    return parsed_data

def sanitize_filename(name):
    # Reemplazar caracteres inválidos por guiones bajos
    return re.sub(r'[\\/*?:"<>|]', "_", name)

def plot_metric_vs_time(data, metric, title, route):
    if not data:
        print(f"No hay datos para graficar {metric}")
        return
        
    plt.figure(figsize=(12, 8))
    
    if not any(metric in entry for entry in data):
        print(f"La métrica {metric} no existe en los datos")
        return
        
    # Mapeo de métricas a etiquetas en español
    metric_labels = {
        'ramUsageDiff': 'Uso de RAM (%)',  # Añadido '%' al label de RAM
        'cpuUsageDiff': 'Uso de CPU (%)',  # Ya existente
        'transactionCost': 'Costo de Transacción',
        'latency': 'Latencia'
    }
    
    # Obtener la etiqueta correspondiente o usar el nombre original si no está mapeado
    y_label = metric_labels.get(metric, metric)
    
    # Mapeo de métricas a títulos en español
    title_labels = {
        'ramUsageDiff': 'Uso de RAM vs Tiempo',
        'cpuUsageDiff': 'Uso de CPU vs Tiempo',
        'transactionCost': 'Costo de Transacción vs Tiempo',
        'latency': 'Latencia vs Tiempo'
    }

    # Obtener el título en español correspondiente
    title_label = title_labels.get(metric, title)
    
    # Agrupar por tipo de prueba y número total de transacciones
    test_groups = {}
    for entry in data:
        key = (entry['testType'], entry['totalTransactions'])
        if key not in test_groups:
            test_groups[key] = []
        test_groups[key].append(entry)

    # Plotear cada tipo de test
    for (test_type, total_tx), entries in test_groups.items():
        # Obtener los timestamps en segundos desde el inicio
        all_times = []
        all_metrics = []
        for entry in entries:
            time_seconds = (entry['timestamp'] - entries[0]['timestamp']).total_seconds()
            all_times.append(time_seconds)
            all_metrics.append(float(entry[metric]) if entry[metric] else 0.0)
        
        label = f'{test_type} - {total_tx} tx'
        plt.plot(all_times, all_metrics, label=label, marker='o', markersize=2)
        print(f"Graficando {len(all_times)} puntos para {label}")

    plt.xlabel('Tiempo (segundos)')  # Cambiado a 'Tiempo (segundos)'
    plt.ylabel(y_label)  # Usar la etiqueta en español correspondiente

    #if metric == 'cpuUsageDiff' or metric == 'ramUsageDiff':  # Establecer el límite inferior del eje Y a 0% para CPU y RAM
    #    plt.ylim(bottom=0)

    plt.title(f"{title_label} - {route}")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True)
    
    # Sanitizar el nombre de la ruta para usarlo en el nombre del archivo
    sanitized_route = sanitize_filename(route)
    try:
        plt.savefig(f'{metric}_vs_time_{sanitized_route}.png', bbox_inches='tight')
        print(f"Gráfica guardada: {metric}_vs_time_{sanitized_route}.png")
    except Exception as e:
        print(f"Error guardando la gráfica {metric}: {str(e)}")
    
    plt.close()

def plot_metric_vs_transaction(data, metric, title, route):
    if not data:
        print(f"No hay datos para graficar {metric}")
        return
        
    plt.figure(figsize=(12, 8))
    
    if not any(metric in entry for entry in data):
        print(f"La métrica {metric} no existe en los datos")
        return
        
    # Mapeo de métricas a etiquetas en español
    metric_labels = {
        'ramUsageDiff': 'Uso de RAM (%)',  # Añadido '%' al label de RAM
        'cpuUsageDiff': 'Uso de CPU (%)',  # Ya existente
        'transactionCost': 'Costo de Transacción',
        'latency': 'Latencia'
    }
    
    # Obtener la etiqueta correspondiente o usar el nombre original si no está mapeado
    y_label = metric_labels.get(metric, metric)
    
    # Mapeo de métricas a títulos en español
    title_labels = {
        'ramUsageDiff': 'Uso de RAM vs Id de Transacción',
        'cpuUsageDiff': 'Uso de CPU vs Id de Transacción',
        'transactionCost': 'Costo de Transacción vs Id de Transacción',
        'latency': 'Latencia vs Id de Transacción'
    }

    # Obtener el título en español correspondiente
    title_label = title_labels.get(metric, title)
    
    # Agrupar por tipo de prueba y número total de transacciones
    test_groups = {}
    for entry in data:
        key = (entry['testType'], entry['totalTransactions'], entry['route'])  # Incluir ruta en la agrupación
        if key not in test_groups:
            test_groups[key] = []
        test_groups[key].append(entry)

    # Plotear cada tipo de test
    for (test_type, total_tx, route), entries in test_groups.items():
        # Obtener los requestNumbers y las métricas correspondientes
        request_numbers = [entry['requestNumber'] for entry in entries]
        metric_values = [float(entry[metric]) if entry[metric] else 0.0 for entry in entries]
        
        label = f'{test_type} - {total_tx} tx - {route}'
        plt.plot(request_numbers, metric_values, label=label, marker='o', markersize=2)
        print(f"Graficando {len(request_numbers)} puntos para {label}")

    plt.xlabel('Id de transacción')  # Cambiado a 'Id de transacción'
    plt.ylabel(y_label)  # Usar la etiqueta en español correspondiente

    #if metric == 'cpuUsageDiff' or metric == 'ramUsageDiff':  # Establecer el límite inferior del eje Y a 0% para CPU y RAM
    #    plt.ylim(bottom=0)

    plt.title(f"{title_label} - {route}")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True)
    
    # Sanitizar el nombre de la ruta para usarlo en el nombre del archivo
    sanitized_route = sanitize_filename(route)
    try:
        plt.savefig(f'{metric}_vs_transaction_{sanitized_route}.png', bbox_inches='tight')  # Cambiado el nombre del archivo
        print(f"Gráfica guardada: {metric}_vs_transaction_{sanitized_route}.png")
    except Exception as e:
        print(f"Error guardando la gráfica {metric}: {str(e)}")
    
    plt.close()

def plot_transaction_cost_vs_length(data):
    # Filtrar solo las solicitudes POST
    post_data = [entry for entry in data if entry['method'].upper() == 'POST']
    
    # Remover la gráfica y generar una tabla con media, mediana y moda
    costs = [entry['transactionCost'] for entry in post_data if entry['transactionCost'] is not None]
    lengths = [entry['parametersLength'] for entry in post_data if entry['parametersLength'] is not None]
    
    if not costs or not lengths:
        print("No hay datos suficientes para generar la tabla de costo de transacción por longitud para POST.")
        return
    
    # Calcular estadísticas
    cost_mean = mean(costs)
    cost_median = median(costs)
    cost_mode = Counter(costs).most_common(1)[0][0]
    
    length_mean = mean(lengths)
    length_median = median(lengths)
    length_mode = Counter(lengths).most_common(1)[0][0]
    
    # Crear la tabla
    table = {
        'Métrica': ['Costo de Transacción', 'Longitud de Parámetros'],
        'Media': [cost_mean, length_mean],
        'Mediana': [cost_median, length_median],
        'Moda': [cost_mode, length_mode]
    }
    
    df_table = pd.DataFrame(table)
    print("Tabla de Costo de Transacción por Longitud (Solo POST):")
    print(df_table)
    df_table.to_csv('transaction_cost_per_length_stats_post.csv', index=False)

def calculate_statistics(data, metric):
    values = [entry[metric] for entry in data]
    return {
        'mean': mean(values),
        'median': median(values),
        'mode': Counter(values).most_common(1)[0][0]
    }

def generate_statistics_table(data, metrics):
    stats_table = []
    for route in set(entry['route'] for entry in data):
        for test_type in set(entry['testType'] for entry in data if entry['route'] == route):
            subset = [entry for entry in data if entry['route'] == route and entry['testType'] == test_type]
            stats = {'Route': route, 'Test Type': test_type}
            for metric in metrics:
                metric_values = [entry[metric] for entry in subset if entry[metric] is not None]
                if metric_values:
                    metric_stats = {
                        'mean': mean(metric_values),
                        'median': median(metric_values),
                        'mode': Counter(metric_values).most_common(1)[0][0]
                    }
                else:
                    metric_stats = {'mean': 'N/A', 'median': 'N/A', 'mode': 'N/A'}
                stats[f'{metric}_mean'] = metric_stats['mean']
                stats[f'{metric}_median'] = metric_stats['median']
                stats[f'{metric}_mode'] = metric_stats['mode']
            stats_table.append(stats)
    
    df = pd.DataFrame(stats_table)
    return df

def calculate_transaction_speed(data, interval='60S'):
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp', inplace=True)
    transaction_speed = df.resample(interval).size()
    plt.figure(figsize=(10, 6))
    transaction_speed.plot()
    plt.xlabel('Time')
    plt.ylabel('Transactions per Interval')
    plt.title(f'Transaction Speed over Time (Interval: {interval})')
    #plt.show()
    plt.savefig('transaction_speed_in_time.png')
    return transaction_speed

def plot_gas_consumption(data, route):
    if not data:
        print("No hay datos para graficar el consumo de gas")
        return

    plt.figure(figsize=(12, 8))
    gas = [entry['refTime'] + entry['proofSize'] for entry in data]
    transactions = [entry['requestNumber'] for entry in data]

    plt.plot(transactions, gas, marker='o', markersize=2, label='Consumo de Gas')
    plt.xlabel('Id de transacción')
    plt.ylabel('Gas Consumido (refTime + proofSize)')
    plt.title(f'Consumo de Gas vs Id de Transacción - {route}')
    plt.legend()
    plt.grid(True)

    sanitized_route = sanitize_filename(route)
    try:
        plt.savefig(f'gas_consumption_vs_transaction_{sanitized_route}.png', bbox_inches='tight')
        print(f"Gráfica de consumo de gas guardada: gas_consumption_vs_transaction_{sanitized_route}.png")
    except Exception as e:
        print(f"Error guardando la gráfica de gas: {str(e)}")

    plt.close()

def main():
    data = read_data()
    if not data:
        print("No se pudieron cargar datos del archivo")
        return
        
    parsed_data = parse_data(data)
    if not parsed_data:
        print("No hay datos válidos para procesar")
        return
    
    print(f"Se procesaron exitosamente {len(parsed_data)} entradas de datos")
    
    # Gráficos actualizados
    metrics = ['cpuUsageDiff', 'ramUsageDiff', 'transactionCost']
    routes = set(entry['route'] for entry in parsed_data)
    print(f"Rutas encontradas: {routes}")
    for route in routes:
        route_data = [entry for entry in parsed_data if entry['route'] == route]
        for metric in ['cpuUsageDiff', 'ramUsageDiff', 'transactionCost']:
            plot_metric_vs_transaction(route_data, metric, f'{metric} vs Número de Transacción', route)  
            plot_metric_vs_time(route_data, metric, f'{metric} vs Tiempo', route)
        plot_gas_consumption(route_data, route)
    
    # Generar tabla de Costo Transaccional por Longitud de Parámetros
    plot_transaction_cost_vs_length(parsed_data)
    
    # Velocidad de Transacción
    transaction_speed = calculate_transaction_speed(parsed_data, interval='60s')
    
    # Tabla de estadísticas (Media, Moda, Mediana) basada en ruta
    metrics = ['cpuUsageDiff', 'ramUsageDiff', 'transactionCost', 'latency']
    stats_table = generate_statistics_table(parsed_data, metrics)
    

    print("Estadisticas:")
    print(stats_table)
    stats_table.to_csv('statistics_summary.csv', index=False)

if __name__ == "__main__":
    main()
