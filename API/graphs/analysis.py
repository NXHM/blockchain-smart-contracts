from statistics import mean, median, mode, StatisticsError
import pandas as pd

def generate_statistics_table(data, metrics):
    """
    Genera una tabla de estadísticas (media, mediana) para las métricas dadas,
    agrupadas por ruta y tipo de prueba.
    """
    if not data:
        return pd.DataFrame()

    stats_table = []
    # Obtener y ordenar rutas y tipos de prueba para un resultado consistente
    routes = sorted(list(set(entry['route'] for entry in data)))
    
    for route in routes:
        test_types = sorted(list(set(entry['testType'] for entry in data if entry['route'] == route)))
        for test_type in test_types:
            subset = [entry for entry in data if entry['route'] == route and entry['testType'] == test_type]
            if not subset:
                continue
            
            stats = {'Route': route, 'Test Type': test_type}
            for metric in metrics:
                values = [entry[metric] for entry in subset if entry.get(metric) is not None]
                if values:
                    stats[f'{metric}_mean'] = mean(values)
                    stats[f'{metric}_median'] = median(values)
                    try:
                        stats[f'{metric}_mode'] = mode(values)
                    except StatisticsError:
                        stats[f'{metric}_mode'] = 'N/A' # No hay un único modo
                else:
                    stats[f'{metric}_mean'] = 'N/A'
                    stats[f'{metric}_median'] = 'N/A'
                    stats[f'{metric}_mode'] = 'N/A'
            stats_table.append(stats)
    
    return pd.DataFrame(stats_table)

def generate_post_cost_table(data):
    """
    Calcula y muestra una tabla con estadísticas del costo de transacción
    para todas las solicitudes de tipo POST.
    """
    post_data = [entry for entry in data if entry.get('method', '').upper() == 'POST']
    
    if not post_data:
        print("No se encontraron solicitudes POST para analizar el costo.")
        return

    costs = [entry['transactionCost'] for entry in post_data if 'transactionCost' in entry]
    
    if not costs:
        print("No hay datos de costos para las solicitudes POST.")
        return

    table = {
        'Métrica': ['Costo de Transacción (POST)'],
        'Media': [mean(costs)],
        'Mediana': [median(costs)],
    }
    try:
        table['Moda'] = [mode(costs)]
    except StatisticsError:
        table['Moda'] = ['N/A']

    df_table = pd.DataFrame(table)
    print("\nTabla de Costo de Transacción (Solo POST):")
    print(df_table)
    
    # Guardar en CSV
    df_table.to_csv('transaction_cost_stats_post.csv', index=False)
    print("Tabla de costos para POST guardada en 'transaction_cost_stats_post.csv'")
