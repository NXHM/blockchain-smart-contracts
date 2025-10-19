import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from utils import sanitize_filename

# --- FUNCIÓN DE UTILIDAD PARA GRAFICAR ---

def create_and_save_plot(plot_data, title, x_label, y_label, filename):
    """
    Función genérica para crear y guardar un gráfico.
    - plot_data: una lista de diccionarios, cada uno con 'x', 'y', 'label'.
    """
    if not plot_data:
        print(f"No hay datos para graficar en {filename}")
        return

    plt.figure(figsize=(12, 8))
    
    for series in plot_data:
        plt.plot(series['x'], series['y'], label=series['label'], marker='o', markersize=3, linestyle='-')

    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid(True)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    
    try:
        plt.savefig(filename, bbox_inches='tight')
        print(f"Gráfica guardada: {filename}")
    except Exception as e:
        print(f"Error guardando la gráfica {filename}: {e}")
    
    plt.close()

# --- FUNCIONES ESPECIALIZADAS PARA CADA TIPO DE GRÁFICO ---

def plot_metric_vs_time(data, metric, route):
    """Prepara los datos y llama a la función de ploteo para métricas vs. tiempo."""
    metric_labels = {
        'ramUsageDiff': 'Uso de RAM (%)', 
        'cpuUsageDiff': 'Uso de CPU (%)', 
        'transactionCost': 'Costo de Transacción',
        'latency': 'Latencia (ms)'
    }
    title_labels = {
        'ramUsageDiff': 'Uso de RAM vs Tiempo', 
        'cpuUsageDiff': 'Uso de CPU vs Tiempo', 
        'transactionCost': 'Costo de Transacción vs Tiempo',
        'latency': 'Latencia vs Tiempo'
    }
    
    test_groups = {}
    for entry in data:
        key = (entry['testType'], entry['totalTransactions'])
        if key not in test_groups:
            test_groups[key] = []
        test_groups[key].append(entry)

    plot_data = []
    # Asegurar que los grupos se procesen en un orden consistente
    for key in sorted(test_groups.keys()):
        entries = sorted(test_groups[key], key=lambda x: x['timestamp'])
        if not entries:
            continue
        start_time = entries[0]['timestamp']
        series = {
            'x': [(entry['timestamp'] - start_time).total_seconds() for entry in entries],
            'y': [entry[metric] for entry in entries],
            'label': f'{key[0]} - {key[1]} tx'
        }
        plot_data.append(series)

    sanitized_route = sanitize_filename(route)
    title = f"{title_labels.get(metric, metric)} - {route}"
    filename = f'{metric}_vs_time_{sanitized_route}.png'
    create_and_save_plot(plot_data, title, 'Tiempo (segundos)', metric_labels.get(metric, metric), filename)

def plot_metric_vs_transaction(data, metric, route):
    """Prepara los datos y llama a la función de ploteo para métricas vs. ID de transacción."""
    metric_labels = {
        'ramUsageDiff': 'Uso de RAM (%)', 
        'cpuUsageDiff': 'Uso de CPU (%)', 
        'transactionCost': 'Costo de Transacción',
        'latency': 'Latencia (ms)'
    }
    title_labels = {
        'ramUsageDiff': 'Uso de RAM vs Id de Transacción', 
        'cpuUsageDiff': 'Uso de CPU vs Id de Transacción', 
        'transactionCost': 'Costo de Transacción vs Id de Transacción',
        'latency': 'Latencia vs Id de Transacción'
    }

    test_groups = {}
    for entry in data:
        key = (entry['testType'], entry['totalTransactions'])
        if key not in test_groups:
            test_groups[key] = []
        test_groups[key].append(entry)

    plot_data = []
    # Asegurar un orden consistente
    for key in sorted(test_groups.keys()):
        entries = sorted(test_groups[key], key=lambda x: x['requestNumber'])
        series = {
            'x': [entry['requestNumber'] for entry in entries],
            'y': [entry[metric] for entry in entries],
            'label': f'{key[0]} - {key[1]} tx'
        }
        plot_data.append(series)

    sanitized_route = sanitize_filename(route)
    title = f"{title_labels.get(metric, metric)} - {route}"
    filename = f'{metric}_vs_transaction_{sanitized_route}.png'
    create_and_save_plot(plot_data, title, 'Id de transacción', metric_labels.get(metric, metric), filename)

def plot_gas_consumption(data, route):
    """Prepara y plotea el consumo de gas vs. ID de transacción."""
    # Filtrar datos para asegurar que tienen la información necesaria
    gas_data = [e for e in data if e.get('transactionCost', 0) > 0]
    if not gas_data:
        print(f"No hay datos de consumo de gas para la ruta {route}")
        return

    plot_data = [{
        'x': [entry['requestNumber'] for entry in gas_data],
        'y': [entry['transactionCost'] for entry in gas_data],
        'label': 'Consumo de Gas'
    }]
    
    sanitized_route = sanitize_filename(route)
    title = f'Consumo de Gas vs Id de Transacción - {route}'
    filename = f'gas_consumption_vs_transaction_{sanitized_route}.png'
    create_and_save_plot(plot_data, title, 'Id de transacción', 'Gas Consumido (refTime + proofSize)', filename)

def plot_latency_vs_cost(data):
    """
    Genera un gráfico de dispersión para correlacionar la latencia y el costo de transacción.
    """
    if not data:
        print("No hay datos para generar el gráfico de latencia vs. costo.")
        return

    df = pd.DataFrame(data)
    # Filtrar solo datos que tengan costo (ej. excluir peticiones GET)
    df = df[df['transactionCost'] > 0]

    if df.empty:
        print("No hay datos con costo de transacción para graficar.")
        return

    plt.figure(figsize=(12, 8))
    
    # Usar seaborn para un gráfico de dispersión con colores por categoría (ruta)
    sns.scatterplot(data=df, x='latency', y='transactionCost', hue='route', alpha=0.6, s=50)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

    plt.xlabel('Latencia (ms)')
    plt.ylabel('Costo de Transacción (Gas)')
    plt.title('Correlación entre Latencia y Costo de Transacción')
    plt.grid(True)
    
    filename = 'latency_vs_cost_correlation.png'
    try:
        plt.savefig(filename, bbox_inches='tight')
        print(f"Gráfica guardada: {filename}")
    except Exception as e:
        print(f"Error al guardar la gráfica '{filename}': {e}")
    
    plt.close()

def plot_transaction_speed(data, interval_seconds=60):
    """
    Calcula y grafica la velocidad (TPS) en intervalos de tiempo para cada grupo de prueba.
    """
    if not data:
        print("No hay datos para calcular la velocidad de transacción.")
        return

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    plt.figure(figsize=(12, 8))
    
    # Agrupar por tipo de prueba y número de transacciones
    grouped = df.groupby(['testType', 'totalTransactions'])
    
    plot_data = []
    for name, group in grouped:
        # Ignorar grupos con menos de 100 transacciones para eliminar ruido
        if len(group) < 100:
            continue
        
        # Calcular tiempo relativo para cada grupo
        start_time = group['timestamp'].min()
        # Crear un índice de tiempo relativo para poder usar resample
        group.index = group['timestamp'] - start_time
        
        # Contar transacciones por intervalo de tiempo
        interval_str = f'{interval_seconds}s'
        transaction_counts = group.resample(interval_str).size()
        
        # Calcular TPS (Transacciones por Segundo)
        tps = transaction_counts / interval_seconds
        
        # Preparar datos para el plot: el eje x son los segundos desde el inicio
        series = {
            'x': tps.index.total_seconds(),
            'y': tps.values,
            'label': f'{name[0]} - {name[1]} tx'
        }
        plot_data.append(series)

    if not plot_data:
        print("No hay suficientes datos (grupos con >100 tx) para generar el gráfico de velocidad.")
        plt.close() # Cerrar la figura vacía
        return

    # Llamar a la función de ploteo genérica
    title = 'Velocidad de Transacción en el Tiempo por Tipo de Prueba'
    x_label = 'Tiempo Transcurrido (segundos)'
    y_label = f'Velocidad (Transacciones por Segundo, promedio en {interval_seconds}s)'
    filename = 'transaction_speed_summary.png'
    
    create_and_save_plot(plot_data, title, x_label, y_label, filename)
