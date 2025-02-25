// tip_manager.js

require('dotenv').config(); // Cargar variables de entorno

// Obtiene el valor total de transacciones desde el archivo .env o utiliza un valor por defecto
const totalTransactions = parseInt(process.env.TOTAL_REQUESTS) || 100;

// Verifica si el tip será aleatorio o decremental basado en la variable TIP_RANDOM
const isTipRandom = process.env.TIP_RANDOM === 'true';

// Variable global para el tip decremental, que comienza en el valor total de transacciones
let decrementalTip = totalTransactions;

/**
 * Función para generar un tip aleatorio entre un rango específico
 * @returns {number} El valor del tip aleatorio entre 1 y el total de transacciones 
 */
function generateRandomTip() {
    return Math.floor(Math.random() * totalTransactions ) + 1;
}

/**
 * Función para manejar el decremento del tip.
 * @returns {number} El valor del tip decrementado
 */
function getDecrementalTip() {
    if (decrementalTip > 0) {
        decrementalTip -= 1;
    }
    return decrementalTip;
}

/**
 * Función principal para obtener el tip basado en la configuración
 * @returns {number} El valor del tip basado en la configuración del archivo .env
 */
function getTip() {
    if (isTipRandom) {
        return generateRandomTip();
    } else {
        return getDecrementalTip();
    }
}

module.exports = {
    getTip
};
