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
const TOTAL_REQUESTS = parseInt(process.env.TOTAL_REQUESTS) || 50; // Cantidad de solicitudes totales
const SIMULTANEOUS_REQUESTS = 10; // Cantidad de solicitudes simultáneas por lote

const FULL_URL = `http://${HOST}:${PORT}`;
const ACCOUNT_IDS_FILE = path.join(__dirname, 'account_ids.txt');

// Función para cargar las AccountIDs desde el archivo
function loadAccountIds() {
    try {
        const data = fs.readFileSync(ACCOUNT_IDS_FILE, 'utf8');
        return data.split('\n').filter(line => line.trim() !== '');
    } catch (error) {
        console.error('Error reading account_ids.txt:', error.message);
        return [];
    }
}

// --- FUNCIONES DE PRUEBA ---

async function runCreateUserTest(mode) {
    console.log(`Running Create User test in ${mode} mode...`);
    const groupID = uuidv4();
    let requestNumber = 0;

    const makeRequest = async () => {
        requestNumber++;
        const name = faker.name.findName();
        const email = faker.internet.email();
        try {
            await axios.post(`${FULL_URL}/create_user`, {
                name: name,
                email: email
            }, {
                params: {
                    requestNumber: requestNumber,
                    totalTransactions: TOTAL_REQUESTS,
                    testType: mode,
                    groupID: groupID
                }
            });
        } catch (error) {
            console.error('Error in Create User request:', error.message);
        }
    };

    if (mode === 'sequential') {
        for (let i = 0; i < TOTAL_REQUESTS; i++) {
            await makeRequest();
        }
    } else if (mode === 'concurrent') {
        const promises = [];
        for (let i = 0; i < TOTAL_REQUESTS; i++) {
            promises.push(makeRequest());
        }
        await Promise.all(promises);
    } else if (mode === 'batch') {
        for (let i = 0; i < TOTAL_REQUESTS; i += SIMULTANEOUS_REQUESTS) {
            const batchPromises = [];
            for (let j = 0; j < SIMULTANEOUS_REQUESTS && (i + j) < TOTAL_REQUESTS; j++) {
                batchPromises.push(makeRequest());
            }
            await Promise.all(batchPromises);
        }
    }
    console.log('Create User test finished.');
}

async function runAssignRoleTest(mode) {
    console.log(`Running Assign Role test in ${mode} mode...`);
    const accounts = loadAccountIds();
    if (accounts.length === 0) {
        console.log('No accounts found in account_ids.txt. Skipping Assign Role test.');
        return;
    }
    const groupID = uuidv4();
    let requestNumber = 0;
    const totalRequests = accounts.length;

    const makeRequest = async (accountId) => {
        requestNumber++;
        const role = Math.round(Math.random()); // 0 o 1
        try {
            await axios.post(`${FULL_URL}/assign_role`, {
                accountId: accountId,
                role: role
            }, {
                params: {
                    requestNumber: requestNumber,
                    totalTransactions: totalRequests,
                    testType: mode,
                    groupID: groupID
                }
            });
        } catch (error) {
            console.error(`Error in Assign Role request for ${accountId}:`, error.message);
        }
    };

    if (mode === 'sequential') {
        for (const accountId of accounts) {
            await makeRequest(accountId);
        }
    } else if (mode === 'concurrent') {
        const promises = accounts.map(accountId => makeRequest(accountId));
        await Promise.all(promises);
    } else if (mode === 'batch') {
        for (let i = 0; i < accounts.length; i += SIMULTANEOUS_REQUESTS) {
            const batch = accounts.slice(i, i + SIMULTANEOUS_REQUESTS);
            const batchPromises = batch.map(accountId => makeRequest(accountId));
            await Promise.all(batchPromises);
        }
    }
    console.log('Assign Role test finished.');
}

async function runGrantPermissionTest(mode) {
    console.log(`Running Grant Permission test in ${mode} mode...`);
    const accounts = loadAccountIds();
    if (accounts.length < 2) {
        console.log('Need at least 2 accounts for Grant Permission test. Skipping.');
        return;
    }
    const groupID = uuidv4();
    let requestNumber = 0;
    const totalRequests = accounts.length -1;

    const makeRequest = async (granter, grantee) => {
        requestNumber++;
        try {
            await axios.post(`${FULL_URL}/grant_permission`, {
                granter: granter,
                grantee: grantee,
                state: true
            }, {
                params: {
                    requestNumber: requestNumber,
                    totalTransactions: totalRequests,
                    testType: mode,
                    groupID: groupID
                }
            });
        } catch (error) {
            console.error(`Error in Grant Permission request from ${granter} to ${grantee}:`, error.message);
        }
    };

    const granter = accounts[0]; // Usar la primera cuenta como la que otorga permisos
    const grantees = accounts.slice(1);

    if (mode === 'sequential') {
        for (const grantee of grantees) {
            await makeRequest(granter, grantee);
        }
    } else if (mode === 'concurrent') {
        const promises = grantees.map(grantee => makeRequest(granter, grantee));
        await Promise.all(promises);
    } else if (mode === 'batch') {
        for (let i = 0; i < grantees.length; i += SIMULTANEOUS_REQUESTS) {
            const batch = grantees.slice(i, i + SIMULTANEOUS_REQUESTS);
            const batchPromises = batch.map(grantee => makeRequest(granter, grantee));
            await Promise.all(batchPromises);
        }
    }
    console.log('Grant Permission test finished.');
}

async function runHasPermissionTest(mode) {
    console.log(`Running Has Permission test in ${mode} mode...`);
    const accounts = loadAccountIds();
    if (accounts.length < 2) {
        console.log('Need at least 2 accounts for Has Permission test. Skipping.');
        return;
    }
    const groupID = uuidv4();
    let requestNumber = 0;
    const totalRequests = accounts.length - 1;

    const makeRequest = async (granter, grantee) => {
        requestNumber++;
        try {
            await axios.get(`${FULL_URL}/has_permission/${granter}/${grantee}`, {
                params: {
                    requestNumber: requestNumber,
                    totalTransactions: totalRequests,
                    testType: mode,
                    groupID: groupID
                }
            });
        } catch (error) {
            console.error(`Error in Has Permission request from ${granter} to ${grantee}:`, error.message);
        }
    };

    const granter = accounts[0];
    const grantees = accounts.slice(1);

    if (mode === 'sequential') {
        for (const grantee of grantees) {
            await makeRequest(granter, grantee);
        }
    } else if (mode === 'concurrent') {
        const promises = grantees.map(grantee => makeRequest(granter, grantee));
        await Promise.all(promises);
    } else if (mode === 'batch') {
        for (let i = 0; i < grantees.length; i += SIMULTANEOUS_REQUESTS) {
            const batch = grantees.slice(i, i + SIMULTANEOUS_REQUESTS);
            const batchPromises = batch.map(grantee => makeRequest(granter, grantee));
            await Promise.all(batchPromises);
        }
    }
    console.log('Has Permission test finished.');
}

// --- FUNCIÓN CORREGIDA ---
async function runGetRoleTest(mode) {
    console.log(`Running Get Role test in ${mode} mode...`);
    const accounts = loadAccountIds();
    if (accounts.length === 0) {
        console.log('No accounts found in account_ids.txt. Skipping Get Role test.');
        return;
    }
    const groupID = uuidv4();
    let requestNumber = 0;
    const totalRequests = accounts.length;

    const makeRequest = async (accountId) => {
        requestNumber++;
        try {
            await axios.get(`${FULL_URL}/role/${accountId}`, {
                params: {
                    requestNumber: requestNumber,
                    totalTransactions: totalRequests,
                    testType: mode,
                    groupID: groupID
                }
            });
        } catch (error) {
            console.error(`Error in Get Role request for ${accountId}:`, error.message);
        }
    };

    if (mode === 'sequential') {
        for (const accountId of accounts) {
            await makeRequest(accountId);
        }
    } else if (mode === 'concurrent') {
        const promises = accounts.map(accountId => makeRequest(accountId));
        await Promise.all(promises);
    } else if (mode === 'batch') {
        for (let i = 0; i < accounts.length; i += SIMULTANEOUS_REQUESTS) {
            const batch = accounts.slice(i, i + SIMULTANEOUS_REQUESTS);
            const batchPromises = batch.map(accountId => makeRequest(accountId));
            await Promise.all(batchPromises);
        }
    }

    console.log('Get Role test finished.');
}

async function runCreateUserWithDynamicGasTest(mode) {
    console.log(`Running Create User with Dynamic Gas test in ${mode} mode...`);
    const groupID = uuidv4();
    let requestNumber = 0;

    const makeRequest = async () => {
        requestNumber++;
        const name = faker.name.findName();
        const email = faker.internet.email();
        try {
            await axios.post(`${FULL_URL}/create_user_with_dynamic_gas`, {
                name: name,
                email: email
            }, {
                params: {
                    requestNumber: requestNumber,
                    totalTransactions: TOTAL_REQUESTS,
                    testType: mode,
                    groupID: groupID
                }
            });
        } catch (error) {
            console.error('Error in Create User with Dynamic Gas request:', error.message);
        }
    };

    if (mode === 'sequential') {
        for (let i = 0; i < TOTAL_REQUESTS; i++) {
            await makeRequest();
        }
    } else if (mode === 'concurrent') {
        const promises = [];
        for (let i = 0; i < TOTAL_REQUESTS; i++) {
            promises.push(makeRequest());
        }
        await Promise.all(promises);
    } else if (mode === 'batch') {
        for (let i = 0; i < TOTAL_REQUESTS; i += SIMULTANEOUS_REQUESTS) {
            const batchPromises = [];
            for (let j = 0; j < SIMULTANEOUS_REQUESTS && (i + j) < TOTAL_REQUESTS; j++) {
                batchPromises.push(makeRequest());
            }
            await Promise.all(batchPromises);
        }
    }
    console.log('Create User with Dynamic Gas test finished.');
}


// --- MENÚ PRINCIPAL ---

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function showMenu() {
    console.log('\n--- Stress Testing Menu ---');
    console.log('1. Run all tests (Sequential)');
    console.log('2. Run all tests (Concurrent)');
    console.log('3. Run all tests (Batch)');
    console.log('4. Run Create User test');
    console.log('5. Run Assign Role test');
    console.log('6. Run Grant Permission test');
    console.log('7. Run Has Permission test');
    console.log('8. Run Get Role test');
    console.log('9. Run Create User with Dynamic Gas test');
    console.log('0. Exit');
}

async function runSelectedTests(tests, mode) {
    for (const test of tests) {
        await test(mode);
    }
}

const allTests = [
    runCreateUserTest,
    runAssignRoleTest,
    runGrantPermissionTest,
    runHasPermissionTest,
    runGetRoleTest,
    runCreateUserWithDynamicGasTest
];

function askForMode(testFunction) {
    rl.question('Select mode (1: Sequential, 2: Concurrent, 3: Batch): ', async (modeChoice) => {
        let mode;
        switch (modeChoice) {
            case '1': mode = 'sequential'; break;
            case '2': mode = 'concurrent'; break;
            case '3': mode = 'batch'; break;
            default: console.log('Invalid mode.'); main(); return;
        }
        await testFunction(mode);
        main();
    });
}

function main() {
    showMenu();
    rl.question('Select an option: ', async (choice) => {
        switch (choice) {
            case '1':
                await runSelectedTests(allTests, 'sequential');
                break;
            case '2':
                await runSelectedTests(allTests, 'concurrent');
                break;
            case '3':
                await runSelectedTests(allTests, 'batch');
                break;
            case '4':
                askForMode(runCreateUserTest);
                return; // Evita que se vuelva a llamar a main() inmediatamente
            case '5':
                askForMode(runAssignRoleTest);
                return;
            case '6':
                askForMode(runGrantPermissionTest);
                return;
            case '7':
                askForMode(runHasPermissionTest);
                return;
            case '8':
                askForMode(runGetRoleTest);
                return;
            case '9':
                askForMode(runCreateUserWithDynamicGasTest);
                return;
            case '0':
                rl.close();
                return;
            default:
                console.log('Invalid option.');
        }
        main(); // Vuelve a mostrar el menú
    });
}

main();
