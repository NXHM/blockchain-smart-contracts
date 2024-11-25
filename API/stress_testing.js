require('dotenv').config();  // Cargar las variables de entorno desde el archivo .env
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');  // Para generar identificadores únicos
const faker = require('faker'); // Para generar datos ficticios
const readline = require('readline'); // Para elegir los métodos desde la consola
const fs = require('fs');
const path = require('path');

// Cargar variables del archivo .env
const HOST = process.env.HOST === '0.0.0.0' ? 'localhost' : process.env.HOST; // Si es 0.0.0.0, usar localhost para las solicitudes
const PORT = process.env.PORT || 3000; // El puerto en el que corre el servidor
const TOTAL_REQUESTS = process.env.TOTAL_REQUESTS || 50; // Cantidad de solicitudes totales
const SIMULTANEOUS_REQUESTS = 10; // Cantidad de solicitudes simultáneas por lote
let MODE = process.env.TEST_TYPE || 'concurrent'; // Puede ser 'sequential', 'concurrent', o 'batch'
const BATCH_WAIT_TIME = process.env.BATCH_WAIT_TIME || 6; // Tiempo de espera entre lotes

// Añadir la variable ALL_TESTS cerca de las otras variables de entorno
const ALL_TESTS = process.env.ALL_TESTS === 'true'; // Convertir el string a booleano

// URL completa de tu API (basada en HOST y PORT)
const FULL_URL = `http://${HOST}:${PORT}`;  // Construir correctamente el URL

// Definir la ruta del archivo donde se almacenan los AccountIds
const ACCOUNT_IDS_FILE = path.join(__dirname, 'account_ids.txt');

// Función para generar datos aleatorios
function generateTestData(mode) {  // Añadir 'mode' como parámetro
    return {
        name: faker.random.alpha({ count: 5 }),
        lastname: faker.random.alpha({ count: 6 }),
        dni: faker.datatype.number({ min: 10000000, max: 99999999 }).toString(),
        email: faker.random.alphaNumeric(10) + '12@gmail.com', // Total de 22 caracteres
        role: faker.datatype.number({ min: 0, max: 1 }),
        // Eliminar 'testType: MODE,' para evitar la sobrescritura
        // testType: MODE,  // Eliminar esta línea
    };
}

// Función para hacer una solicitud POST a /create_user_with_dynamic_gas
async function createUserWithDynamicGas(data, mode) {
    try {
        const response = await axios.post(`${FULL_URL}/create_user_with_dynamic_gas`, { ...data, testType: mode });
        return response.data;
    } catch (error) {
        console.error(`Error creating user with dynamic gas: ${error.message}`);
    }
}

// Modificar la función getRole para aceptar y pasar 'mode'
async function getRole(publicAddress, groupID, requestNumber, totalTransactions, mode) {
    try {
        const response = await axios.get(`${FULL_URL}/role/${publicAddress}`, {
            params: {
                groupID,
                requestNumber,
                totalTransactions,
                testType: mode  // Añadir testType en los parámetros de la consulta
            }
        });
        return response.data;
    } catch (error) {
        console.error(`Error getting role: ${error.message}`);
    }
}

// Función para hacer una solicitud GET a /has_permission/:granter/:grantee
async function hasPermission(granter, grantee, groupID, requestNumber, totalTransactions, mode) {
    try {
        const response = await axios.get(`${FULL_URL}/has_permission/${granter}/${grantee}`, {
            params: {
                groupID,
                requestNumber,
                totalTransactions,
                testType: mode  // Añadir testType en los parámetros de la consulta
            }
        });
        return response.data;
    } catch (error) {
        console.error(`Error obteniendo permiso: ${error.message}`);
    }
}

// Función para obtener la lista de AccountIds desde el archivo txt
function getUserAccountsFromFile() {
    try {
        const data = fs.readFileSync(ACCOUNT_IDS_FILE, 'utf8');
        const accounts = data.split('\n').filter(line => line.trim() !== '');
        return accounts;
    } catch (error) {
        console.error(`Error al leer el archivo de AccountIds: ${error.message}`);
        return [];
    }
}

// Actualizar la función para obtener roles de múltiples usuarios
async function runGetRoleTest(mode) {
    console.log('Obteniendo lista de usuarios desde el archivo...');
    const accounts = getUserAccountsFromFile();
    if (accounts.length === 0) {
        console.log('No se encontraron usuarios para probar.');
        return;
    }

    console.log(`Ejecutando prueba de get_role con ${accounts.length} usuarios...`);

    // Generar un groupID único para esta sesión de pruebas
    const groupID = uuidv4();
    const totalTransactions = accounts.length;
    let requestNumber = 0;

    // Llamadas individuales al endpoint /role/:publicAddress
    for (const accountId of accounts) {
        try {
            requestNumber++;
            const response = await axios.get(`${FULL_URL}/role/${accountId}`, {
                params: {
                    groupID,
                    requestNumber,
                    totalTransactions,
                    testType: mode  // Añadir testType en los parámetros de la consulta
                }
            });
            // ...manejo de la respuesta...
        } catch (error) {
            console.error(`Error al obtener rol: ${error.message}`);
        }
    }
}

// Función para generar datos de prueba para hasPermission
function generatePermissionTestData() {
    // Obtener dos cuentas de AccountIds.txt
    const accounts = getUserAccountsFromFile();
    if (accounts.length < 2) {
        console.log('No hay suficientes usuarios para probar permisos.');
        return null;
    }
    const granter = accounts[Math.floor(Math.random() * accounts.length)];
    let grantee = accounts[Math.floor(Math.random() * accounts.length)];

    // Asegurarse de que granter y grantee no sean iguales
    while (granter === grantee) {
        grantee = accounts[Math.floor(Math.random() * accounts.length)];
    }

    return { granter, grantee };
}

// Función para ejecutar pruebas de hasPermission
async function runHasPermissionTest(mode) {  // Asegurarse de usar 'mode' en lugar de 'MODE'
    console.log('Ejecutando prueba de hasPermission...');
    const totalTransactions = parseInt(TOTAL_REQUESTS);
    const groupID = uuidv4();
    let requestNumber = 0;

    const accounts = getUserAccountsFromFile();
    if (accounts.length < 2) {
        console.log('No hay suficientes usuarios para probar permisos.');
        return;
    }

    // Función para generar datos de prueba
    function getTestData() {
        const granter = accounts[Math.floor(Math.random() * accounts.length)];
        let grantee = accounts[Math.floor(Math.random() * accounts.length)];
        while (granter === grantee) {
            grantee = accounts[Math.floor(Math.random() * accounts.length)];
        }
        return { granter, grantee };
    }

    if (mode === 'sequential') {  // Cambiar de 'MODE' a 'mode'
        // Modo secuencial
        for (let i = 0; i < totalTransactions; i++) {
            const data = generatePermissionTestData();
            if (!data) return;
            requestNumber++;
            // Asignar 'testType' directamente aquí
            data.testType = mode;
            await hasPermission(data.granter, data.grantee, groupID, requestNumber, totalTransactions, mode);
        }
    } else if (mode === 'concurrent') {  // Cambiar de 'MODE' a 'mode'
        // Modo concurrente
        const promises = [];
        for (let i = 0; i < totalTransactions; i++) {
            const data = generatePermissionTestData();
            if (!data) return;
            requestNumber++;
            // Asignar 'testType' directamente aquí
            data.testType = mode;
            promises.push(hasPermission(data.granter, data.grantee, groupID, requestNumber, totalTransactions, mode));
        }
        await Promise.all(promises);
    } else if (mode === 'batch') {  // Cambiar de 'MODE' a 'mode'
        // Modo por lotes
        for (let i = 0; i < totalTransactions; i += SIMULTANEOUS_REQUESTS) {
            const batchPromises = [];
            for (let j = 0; j < SIMULTANEOUS_REQUESTS && i + j < totalTransactions; j++) {
                const data = generatePermissionTestData();
                if (!data) return;
                requestNumber++;
                // Asignar 'testType' directamente aquí
                data.testType = mode;
                batchPromises.push(hasPermission(data.granter, data.grantee, groupID, requestNumber, totalTransactions, mode));
            }
            await Promise.all(batchPromises);
            console.log(`Esperando ${BATCH_WAIT_TIME} segundos antes del siguiente lote...`);
            await new Promise(resolve => setTimeout(resolve, BATCH_WAIT_TIME * 1000));
        }
    } else {
        console.error('Modo de prueba no válido.');
    }
    console.log('Prueba de hasPermission completada');
}

// Modificar la función runSequentialTest para pasar correctamente requestNumber y mode
async function runSequentialTest(endpoint, mode) {  // Añadir 'mode' como parámetro
    // Generar un groupID único para esta sesión de pruebas
    const groupID = uuidv4();
    const totalTransactions = parseInt(TOTAL_REQUESTS); // Obtener el total de transacciones
    console.log(`Running sequential test with ${TOTAL_REQUESTS} requests...`);
    let requestNumber = 0; // Inicializar requestNumber
    for (let i = 0; i < totalTransactions; i++) {
        const data = generateTestData();
        // Añadir el groupID y totalTransactions a los datos enviados en la solicitud
        data.groupID = groupID;
        data.totalTransactions = totalTransactions;
        requestNumber++;
        data.requestNumber = requestNumber;  // Asignar requestNumber al data
        data.testType = mode;  // Asignar testType al data

        console.log(`Executing request ${i + 1}:`, data);

        if (endpoint === 'create_user_with_dynamic_gas') {
            await createUserWithDynamicGas(data, mode);
        } else if (endpoint === 'get_role') {
            await getRole(data.dni, groupID, requestNumber, totalTransactions, mode);  // Pasar los par��metros necesarios
        }
    }
    console.log('Sequential test completed');
}

// Prueba concurrente (las solicitudes se ejecutan simultáneamente)
async function runConcurrentTest(endpoint, mode) {  // Añadir 'mode' como parámetro
    const groupID = uuidv4();
    const totalTransactions = parseInt(TOTAL_REQUESTS);
    console.log(`Running concurrent test with ${TOTAL_REQUESTS} requests...`);
    const promises = [];
    let requestNumber = 0;  // Inicializar requestNumber

    for (let i = 0; i < totalTransactions; i++) {
        requestNumber++;
        
        // Generar datos según el endpoint
        let data;
        if (endpoint === 'create_user_with_dynamic_gas') {
            data = generateTestData(mode);
            data.groupID = groupID;
            data.totalTransactions = totalTransactions;
            data.requestNumber = requestNumber;
            data.testType = mode;
            promises.push(createUserWithDynamicGas(data, mode));
        } 
        else if (endpoint === 'get_role') {
            const accounts = getUserAccountsFromFile();
            if (accounts.length > 0) {
                const randomAccount = accounts[Math.floor(Math.random() * accounts.length)];
                promises.push(getRole(randomAccount, groupID, requestNumber, totalTransactions, mode));
            } else {
                console.log('No hay cuentas disponibles para probar get_role');
                return;
            }
        } 
        else if (endpoint === 'has_permission') {
            const permData = generatePermissionTestData();
            if (permData) {
                promises.push(hasPermission(permData.granter, permData.grantee, groupID, requestNumber, totalTransactions, mode));
            } else {
                console.log('No hay suficientes usuarios para probar has_permission');
                return;
            }
        }
    }
    await Promise.all(promises);
    console.log('Concurrent test completed');
}

// Prueba por lotes (ejecuta solicitudes en grupos)
async function runBatchTest(batchSize, endpoint, mode) {  // Añadir 'mode' como parámetro
    const groupID = uuidv4();
    const totalTransactions = parseInt(TOTAL_REQUESTS);
    console.log(`Running batch test with ${TOTAL_REQUESTS} requests in batches of ${batchSize}...`);
    let requestNumber = 0;  // Inicializar requestNumber

    for (let i = 0; i < totalTransactions; i += batchSize) {
        const batchPromises = [];
        for (let j = 0; j < batchSize && i + j < totalTransactions; j++) {
            const data = generateTestData();
            if (!data) return;
            requestNumber++;
            data.granter = data.granter;
            data.grantee = data.grantee;
            data.groupID = groupID;
            data.totalTransactions = totalTransactions;
            data.requestNumber = requestNumber;  // Asignar requestNumber al data
            data.testType = mode;  // Asignar testType al data

            if (endpoint === 'create_user_with_dynamic_gas') {
                batchPromises.push(createUserWithDynamicGas(data, mode));
            } else if (endpoint === 'get_role') {
                batchPromises.push(getRole(data.dni, groupID, requestNumber, totalTransactions, mode));  // Pasar los parámetros necesarios
            } else if (endpoint === 'has_permission') {
                batchPromises.push(hasPermission(data.granter, data.grantee, groupID, requestNumber, totalTransactions, mode));  // Pasar los parámetros necesarios
            }
        }
        await Promise.all(batchPromises);
        console.log(`Esperando ${BATCH_WAIT_TIME} segundos antes del siguiente lote...`);
        await new Promise(resolve => setTimeout(resolve, BATCH_WAIT_TIME * 1000));
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
3) GET /has_permission
4) ALL
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
                    resolve('has_permission');
                    break;
                case '4':
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

    if (endpoint === 'ALL' || ALL_TESTS) {
        const endpoints = endpoint === 'ALL' 
            ? ['create_user_with_dynamic_gas', 'get_role', 'has_permission']
            : [endpoint];
        const testModes = ALL_TESTS 
            ? ['sequential', 'concurrent', 'batch']
            : [MODE];

        console.log(`\nEjecutando pruebas con la siguiente configuración:`);
        console.log(`Endpoints: ${endpoints.join(', ')}`);
        console.log(`Modos: ${testModes.join(', ')}\n`);

        for (const ep of endpoints) {
            for (const mode of testModes) {
                console.log(`\nEjecutando prueba '${ep}' en modo: ${mode.toUpperCase()}\n`);
                
                if (ep === 'get_role') {
                    await runGetRoleTest(mode);
                } else if (ep === 'has_permission') {
                    await runHasPermissionTest(mode);
                } else {
                    switch (mode) {
                        case 'sequential':
                            await runSequentialTest(ep, mode);
                            break;
                        case 'concurrent':
                            await runConcurrentTest(ep, mode);
                            break;
                        case 'batch':
                            await runBatchTest(SIMULTANEOUS_REQUESTS, ep, mode);
                            break;
                        default:
                            console.error('Modo de prueba no válido');
                    }
                }
                // Esperar un momento entre pruebas para evitar sobrecarga
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }
    } else {
        // Ejecución normal para un solo endpoint y modo
        if (endpoint === 'get_role') {
            await runGetRoleTest(MODE);
        } else if (endpoint === 'has_permission') {
            await runHasPermissionTest(MODE);
        } else {
            switch (MODE) {
                case 'sequential':
                    await runSequentialTest(endpoint, MODE);
                    break;
                case 'concurrent':
                    await runConcurrentTest(endpoint, MODE);
                    break;
                case 'batch':
                    await runBatchTest(SIMULTANEOUS_REQUESTS, endpoint, MODE);
                    break;
                default:
                    console.error('Modo de prueba no válido');
            }
        }
    }
})();
