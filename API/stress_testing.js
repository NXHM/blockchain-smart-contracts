require('dotenv').config();  // Cargar las variables de entorno desde el archivo .env
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');  // Para generar identificadores únicos
const faker = require('faker'); // Para generar datos ficticios
const readline = require('readline'); // Para elegir los métodos desde la consola
const fs = require('fs');

// Cargar variables del archivo .env
const HOST = process.env.HOST === '0.0.0.0' ? 'localhost' : process.env.HOST; // Si es 0.0.0.0, usar localhost para las solicitudes
const PORT = process.env.PORT || 3000; // El puerto en el que corre el servidor
const TOTAL_REQUESTS = process.env.TOTAL_REQUESTS || 50; // Cantidad de solicitudes totales
const SIMULTANEOUS_REQUESTS = 10; // Cantidad de solicitudes simultáneas por lote
const MODE = process.env.TEST_TYPE || 'concurrent'; // Puede ser 'sequential', 'concurrent', o 'batch'

// URL completa de tu API (basada en HOST y PORT)
const FULL_URL = `http://${HOST}:${PORT}`;  // Construir correctamente el URL

// Función para generar datos aleatorios
function generateTestData() {
    return {
        name: faker.name.firstName(),
        lastname: faker.name.lastName(),
        dni: faker.datatype.number({ min: 10000000, max: 99999999 }).toString(),
        email: faker.internet.email(),
        role: faker.datatype.number({ min: 0, max: 1 })
    };
}

// Función para hacer una solicitud POST a /create_user_with_dynamic_gas
async function createUserWithDynamicGas(data) {
    try {
        const response = await axios.post(`${FULL_URL}/create_user_with_dynamic_gas`, data);
        return response.data;
    } catch (error) {
        console.error(`Error creating user with dynamic gas: ${error.message}`);
    }
}

// Función para hacer una solicitud GET a /role
async function getRole(publicAddress) {
    try {
        const response = await axios.get(`${FULL_URL}/role/${publicAddress}`);
        return response.data;
    } catch (error) {
        console.error(`Error getting role: ${error.message}`);
    }
}

// Prueba secuencial (las solicitudes se realizan una por una)
async function runSequentialTest(endpoint) {
    console.log(`Running sequential test with ${TOTAL_REQUESTS} requests...`);
    for (let i = 0; i < TOTAL_REQUESTS; i++) {
        const data = generateTestData();
        console.log(`Executing request ${i + 1}:`, data);

        if (endpoint === 'create_user_with_dynamic_gas') {
            await createUserWithDynamicGas(data);
        } else if (endpoint === 'get_role') {
            await getRole(data.dni);
        }
    }
    console.log('Sequential test completed');
}

// Prueba concurrente (las solicitudes se ejecutan simultáneamente)
async function runConcurrentTest(endpoint) {
    console.log(`Running concurrent test with ${TOTAL_REQUESTS} requests...`);
    const promises = [];
    for (let i = 0; i < TOTAL_REQUESTS; i++) {
        const data = generateTestData();
        if (endpoint === 'create_user_with_dynamic_gas') {
            promises.push(createUserWithDynamicGas(data));
        } else if (endpoint === 'get_role') {
            promises.push(getRole(data.dni));
        }
    }
    await Promise.all(promises);
    console.log('Concurrent test completed');
}

// Prueba por lotes (ejecuta solicitudes en grupos)
async function runBatchTest(batchSize, endpoint) {
    console.log(`Running batch test with ${TOTAL_REQUESTS} requests in batches of ${batchSize}...`);
    for (let i = 0; i < TOTAL_REQUESTS; i += batchSize) {
        const batchPromises = [];
        for (let j = 0; j < batchSize && i + j < TOTAL_REQUESTS; j++) {
            const data = generateTestData();
            if (endpoint === 'create_user_with_dynamic_gas') {
                batchPromises.push(createUserWithDynamicGas(data));
            } else if (endpoint === 'get_role') {
                batchPromises.push(getRole(data.dni));
            }
        }
        await Promise.all(batchPromises);
    }
    console.log('Batch test completed');
}

// Función para seleccionar el endpoint desde la consola
function promptUserForEndpoint() {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        rl.question(`Selecciona el endpoint para testear: 
1) POST /create_user_with_dynamic_gas
2) GET /role
3) ALL
Selecciona la opción: `, (answer) => {
            rl.close();
            switch (answer) {
                case '1':
                    resolve('create_user_with_dynamic_gas');
                    break;
                case '2':
                    resolve('get_role');
                    break;
                case '3':
                    resolve('ALL');
                    break;
                default:
                    console.log('Opción no válida. Seleccionando "create_user_with_dynamic_gas" por defecto.');
                    resolve('create_user_with_dynamic_gas');
            }
        });
    });
}

// Ejecuta la prueba seleccionada
(async () => {
    const endpoint = await promptUserForEndpoint();

    if (endpoint === 'ALL') {
        await runSequentialTest('create_user_with_dynamic_gas');
        await runConcurrentTest('get_role');
    } else {
        switch (MODE) {
            case 'sequential':
                await runSequentialTest(endpoint);
                break;
            case 'concurrent':
                await runConcurrentTest(endpoint);
                break;
            case 'batch':
                await runBatchTest(SIMULTANEOUS_REQUESTS, endpoint);
                break;
            default:
                console.error('Invalid mode selected');
        }
    }
})();
