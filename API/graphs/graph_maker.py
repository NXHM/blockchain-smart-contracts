import os
from dotenv import load_dotenv

# Importar funciones desde los nuevos módulos
from data_processor import read_data, parse_data
from plotting import (
    plot_metric_vs_time,
    plot_metric_vs_transaction,
    plot_gas_consumption,
    plot_latency_vs_cost,
    plot_transaction_speed
)
from analysis import generate_statistics_table, generate_post_cost_table

# Cargar las variables de entorno desde la carpeta previa
load_dotenv(dotenv_path='../.env')

def main():
    """
    Función principal que orquesta la lectura de datos, generación de gráficos y estadísticas.
    """
    # 1. Cargar y procesar datos
    raw_data = read_data()
    if not raw_data:
        print("No se pudieron cargar datos. Finalizando ejecución.")
        return
        
    parsed_data = parse_data(raw_data)
    if not parsed_data:
        print("No hay datos válidos para procesar. Finalizando ejecución.")
        return
    
    # 2. Generar gráficos por cada ruta encontrada
    routes = sorted(list(set(entry['route'] for entry in parsed_data)))
    print(f"\nSe analizarán las siguientes rutas: {routes}")
    
    metrics_to_plot = ['cpuUsageDiff', 'ramUsageDiff', 'transactionCost', 'latency']
    
    for route in routes:
        route_data = [entry for entry in parsed_data if entry['route'] == route]
        if not route_data:
            continue
            
        print(f"\n--- Generando gráficos para la ruta: {route} ---")
        
        for metric in metrics_to_plot:
            # Gráfico de la métrica vs. el ID de la transacción
            plot_metric_vs_transaction(route_data, metric, route)
            # Gráfico de la métrica vs. el tiempo
            plot_metric_vs_time(route_data, metric, route)
        
        # Si la ruta tiene alguna solicitud POST, graficar el consumo de gas
        if any(e.get('method') == 'POST' for e in route_data):
            plot_gas_consumption(route_data, route)

    # 3. Generar informes y gráficos globales
    print("\n--- Generando informes globales ---")
    
    # Gráfico de resumen de Transacciones por Segundo (TPS)
    plot_transaction_speed(parsed_data)

    # Gráfico de correlación entre latencia y costo
    plot_latency_vs_cost(parsed_data)
    
    # Tabla de costos para todas las solicitudes POST
    generate_post_cost_table(parsed_data)
    
    # Tabla resumen de estadísticas
    stats_df = generate_statistics_table(parsed_data, metrics_to_plot)
    
    print("\nResumen de Estadísticas Generales:")
    print(stats_df)
    stats_df.to_csv('statistics_summary.csv', index=False)
    print("Tabla de estadísticas guardada en 'statistics_summary.csv'")

    print("\nAnálisis completado.")

if __name__ == "__main__":
    main()
