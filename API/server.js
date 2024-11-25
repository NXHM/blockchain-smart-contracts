const express = require('express');
const cors = require('cors');
const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { ContractPromise } = require('@polkadot/api-contract');
const { mnemonicGenerate } = require('@polkadot/util-crypto');
const fs = require('fs');
const axios = require('axios');
const path = require('path');
const os = require('os');
require('dotenv').config();
const { logRequestToTxt, logRequestToJson } = require('./logging_middleware');

const { getTip } = require('./tip_manager');

const FABRIC_SERVER_URL = 'http://localhost:4000'; // Dirección del servidor de Hyperledger Fabric

const app = express();
const port = 3000;

// Configuración del CORS
const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN || '*', 
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// Contract Dirección y ABI
const CONTRACT_ADDRESS = '5EpbuBrLhhQ4T9wFcTNA7N2vcrDBKbpFyyja7WRGPsmVhhtY';
const CONTRACT_ABI_PATH = path.resolve(__dirname, '../target/ink/smart_contract/smart_contract.json');

// Performance monitoring configuration
const ENABLE_PERFORMANCE_MONITORING = process.env.ENABLE_PERFORMANCE_MONITORING === 'true';
const LOG_FILE_PATH = path.join(__dirname, 'performance_log.txt');
const logFileJsonPath = path.join(__dirname, 'performance_log.json');
let fileExists = fs.existsSync(logFileJsonPath);
const total_request = process.env.TOTAL_REQUESTS || "100";
const test_type = process.env.TEST_TYPE || 'sequential';

// Middlewares para registrar logs en formato txt y json
app.use(logRequestToTxt);
app.use(logRequestToJson);

const ACCOUNT_IDS_FILE = path.join(__dirname, 'account_ids.txt');

let api;
let contract;
let alice;
// Añadimos la variable global aliceNonce
let aliceNonce; // Variable global para el nonce de Alice

async function init() {
    const wsProvider = new WsProvider('ws://localhost:9944');
    api = await ApiPromise.create({ provider: wsProvider });

    let contractAbi;
    try {
        contractAbi = JSON.parse(fs.readFileSync(CONTRACT_ABI_PATH, 'utf8'));
    } catch (error) {
        console.error(`Error loading contract ABI: ${error.message}`);
        process.exit(1);
    }

    contract = new ContractPromise(api, contractAbi, CONTRACT_ADDRESS);

    // Obtenemos el nonce actual de Alice al inicializar
    const keyring = new Keyring({ type: 'sr25519' });
    alice = keyring.addFromUri('//Alice');
    aliceNonce = await api.rpc.system.accountNextIndex(alice.address);

    // Suscribirse a los eventos
    api.query.system.events((events) => {
        console.log(`\nReceived ${events.length} events:`);

        // Loop through the Vec<EventRecord>
        events.forEach((record) => {
            try {
                // Extract the phase, event and the event types
                const { event, phase } = record;
                const types = event.typeDef;

                // Show what we are busy with
                console.log(`\t${event.section}:${event.method}:: (phase=${JSON.stringify(phase)})`);

                if (event.meta && event.meta.documentation) {
                    console.log(`\t\t${event.meta.documentation.toString()}`);
                }

                // Loop through each of the parameters, displaying the type and data
                event.data.forEach((data, index) => {
                    try {
                        const type = types[index] ? types[index].type : 'undefined';
                        const value = data ? data.toString() : 'undefined';
                        console.log(`\t\t\t${type}: ${value}`);
                    } catch (innerError) {
                        console.error(`Error processing event data: ${innerError.message}`);
                    }
                });

                // Manejar específicamente el evento RoleAssigned
                if (event.section === 'access_control' && event.method === 'RoleAssigned') {
                    const [account, role] = event.data;
                    console.log(`Rol asignado: Cuenta ${account} con rol ${role}`);
                    // Aquí puedes agregar lógica adicional, como actualizar una base de datos
                }

                // Manejar el nuevo evento de error
                if (event.section === 'access_control' && event.method === 'ErrorEvent') {
                    const [message] = event.data;
                    console.error(`Error del contrato: ${message}`);
                }

            } catch (error) {
                console.error(`Error processing event: ${error.message}`);
            }
        });
    });
}

// Mantenemos la función getAndIncrementNonce sin sincronización
function getAndIncrementNonce() {
    const currentNonce = aliceNonce;
    aliceNonce = aliceNonce.addn(1); // Incrementar el nonce
    return currentNonce;
}

// Función opcional para sincronizar el nonce manualmente cuando sea necesario
async function syncNonce() {
    const currentNonce = await api.rpc.system.accountNextIndex(alice.address);
    aliceNonce = currentNonce;
}

// Función para obtener el nonce actual
async function getCurrentNonce(address) {
    return await api.rpc.system.accountNextIndex(address);
}

let transactionCount = 0; // Contador global de transacciones
let lastTransactionTime = Date.now(); // Tiempo de la última transacción
const resetInterval = 5000; // Intervalo de 5 segundos para reiniciar el contador

// Función para actualizar el contador de transacciones y reiniciarlo si pasan 5s
function updateTransactionCount() {
    const currentTime = Date.now();
    
    // Si ha pasado más de 5 segundos desde la última transacción, reiniciamos el contador
    if (currentTime - lastTransactionTime > resetInterval) {
        transactionCount = 0;
    }

    // Incrementamos el contador
    transactionCount += 1;
    lastTransactionTime = currentTime; // Actualizamos el tiempo de la última transacción
}

// Contador inicial de transacciones pendientes
let pendingTransactions = parseInt(total_request); 
let tip = pendingTransactions; // Variable global para el tip, que comienza en el total de transacciones

// Función para crear una nueva cuenta
function createNewAccount(customText = null) {
    const keyring = new Keyring({ type: 'sr25519' });
    const mnemonic = customText || mnemonicGenerate();
    const newAccount = keyring.addFromUri(mnemonic);
    console.log(`New account created: ${newAccount.address}`);
    console.log(`Mnemonic: ${mnemonic}`);
    return {
        address: newAccount.address,
        mnemonic: mnemonic,
        keypair: newAccount
    };
}

// Función para transferir fondos con tip incluido usando transferKeepAlive
async function transferFunds(sender, recipient, amount) {
    const tip = getTip();
    let nonce = getAndIncrementNonce(); // Obtener el nonce local
    const transfer = api.tx.balances.transferKeepAlive(recipient, amount);

    return new Promise((resolve, reject) => {
        function sendTransaction(currentNonce) {
            transfer.signAndSend(sender, { nonce: currentNonce, tip }, ({ events = [], status }) => {
                if (status.isInBlock || status.isFinalized) {
                    console.log(`Transacción incluida en el bloque: ${status.isInBlock ? status.asInBlock : status.asFinalized}`);

                    // Iterar sobre los eventos para capturar errores
                    let hasError = false;
                    events.forEach(({ event: { data, method, section } }) => {
                        if (section === 'system' && method === 'ExtrinsicFailed') {
                            hasError = true;
                            const [dispatchError] = data;
                            if (dispatchError.isModule) {
                                const decoded = api.registry.findMetaError(dispatchError.asModule);
                                const { documentation, name, section } = decoded;
                                const errorMessage = documentation ? documentation.join(' ') : 'Sin documentación disponible';
                                console.error(`Error en la transferencia: ${section}.${name}: ${errorMessage}`);
                                reject(new Error(`${section}.${name}: ${errorMessage}`));
                            } else {
                                console.error(`Error en la transferencia: ${dispatchError.toString()}`);
                                reject(new Error(dispatchError.toString()));
                            }
                        }
                    });

                    if (!hasError) {
                        console.log('Transferencia exitosa');
                        resolve();
                    }
                } else if (status.isError) {
                    console.error('Error en la transferencia:', status);
                    reject(new Error('Error en la transferencia.'));
                }
            }).catch(async (error) => {
                if (error.message.includes('1010') || error.message.includes('Invalid Transaction')) {
                    console.error('Nonce incorrecto, sincronizando y reintentando...');
                    await syncNonce(); // Sincronizar el nonce
                    nonce = getAndIncrementNonce(); // Obtener el nuevo nonce
                    sendTransaction(nonce); // Reintentar la transacción
                } else {
                    console.error(`Error en la transferencia: ${error}`);
                    reject(error);
                }
            });
        }

        sendTransaction(nonce); // Enviar la transacción inicial
    });
}


// Modificar la función addUser para incluir el tip en la transacción
// Modificar la función addUser para incluir el tip en la transacción y guardar el gas consumido
async function addUser(alice, newAccount, userInfo, role, gasLimit, res, mode) {
    updateTransactionCount();
    const numberTransaction = transactionCount;
    const tip = getTip(); // Obtener el tip usando la función getTip
    let nonce = getAndIncrementNonce(); // Obtener el nonce local
    const addUserTx = contract.tx.addUser({ value: 0, gasLimit: gasLimit }, newAccount.address, userInfo, role);

    // Inicializar variables para el gas
    let refTime = null;
    let proofSize = null;

    return new Promise((resolve, reject) => {
        function sendTransaction(currentNonce) {
            addUserTx.signAndSend(alice, { nonce: currentNonce, tip }, ({ events = [], status }) => {
                if (status.isInBlock || status.isFinalized) {
                    console.log(`Transacción incluida en el bloque: ${status.isInBlock ? status.asInBlock : status.asFinalized}`);

                    // Iterar sobre los eventos para capturar errores
                    let hasError = false;
                    events.forEach(({ event: { data, method, section } }) => {
                        if (section === 'system' && method === 'ExtrinsicFailed') {
                            hasError = true;
                            const [dispatchError] = data;
                            if (dispatchError.isModule) {
                                const decoded = api.registry.findMetaError(dispatchError.asModule);
                                const { documentation, name, section } = decoded;
                                const errorMessage = documentation ? documentation.join(' ') : 'Sin documentación disponible';
                                console.error(`Error del contrato: ${section}.${name}: ${errorMessage}`);
                                reject(new Error(`${section}.${name}: ${errorMessage}`));
                            } else {
                                console.error(`Error del contrato: ${dispatchError.toString()}`);
                                reject(new Error(dispatchError.toString()));
                            }
                        } else if (section === 'contracts' && method === 'ContractExecution') {
                            const [contractExecResult] = data;
                            if (contractExecResult.isFailure) {
                                hasError = true;
                                const debugMessage = contractExecResult.asFailure.debugMessage.toString();
                                console.error(`Error en la ejecución del contrato: ${debugMessage}`);
                                reject(new Error(`Error en la ejecución del contrato: ${debugMessage}`));
                            }
                        } else if (section === 'system' && method === 'ExtrinsicSuccess') {
                            // Extraer refTime y proofSize del evento
                            const [dispatchInfo] = data;
                            if (dispatchInfo && dispatchInfo.weight) {
                                res.locals.refTime = dispatchInfo.weight.refTime.toString();
                                res.locals.proofSize = dispatchInfo.weight.proofSize.toString();
                            }
                        }
                    });

                    if (!hasError) {
                        console.log('Transacción exitosa');
                        res.locals.transactionSuccess = true;
                        resolve();
                    }
                } else if (status.isError) {
                    console.error('Error en la transacción:', status);
                    res.locals.transactionSuccess = false;
                    reject(new Error('Error en la transacción.'));
                }
            }).catch(async (error) => {
                if (error.message.includes('1010') || error.message.includes('Invalid Transaction')) {
                    console.error('Nonce incorrecto, sincronizando y reintentando...');
                    await syncNonce(); // Sincronizar el nonce
                    nonce = getAndIncrementNonce(); // Obtener el nuevo nonce
                    sendTransaction(nonce); // Reintentar la transacción
                } else {
                    console.error(`Transacción fallida: ${error}`);
                    
                    // Guardar el estado de fallo y asignar valores predeterminados
                    res.locals.transactionSuccess = false; // Transacción fallida
                    res.locals.refTime = 0; // Gas 0 cuando falla la transacción
                    res.locals.proofSize = 0; // ProofSize 0 cuando falla la transacción
                    res.locals.tip = '0'; // Tip 0 cuando falla la transacción
                    res.locals.transactionCount = 0; // Contador de transacciones 0 cuando falla la transacción
                    reject(error);
                }
            });
        }

        sendTransaction(nonce); // Enviar la transacción inicial
    });
}


// Modificar la función assignRole para incluir el tip en la transacción
async function assignRole(alice, newAccount, role, userInfo, gasLimit) {
    const tip = getTip(); // Obtener el tip usando la función getTip
    const assignRoleTx = contract.tx.assignRole({ value: 0, gasLimit }, newAccount.address, role, userInfo);
    return new Promise((resolve, reject) => {
        assignRoleTx.signAndSend(alice, { tip }, (result) => {
            if (result.status.isInBlock) {
                console.log(`Transaction included at blockHash ${result.status.asInBlock}`);
            } else if (result.status.isFinalized) {
                console.log(`Transaction finalized at blockHash ${result.status.asFinalized}`);
                resolve(result);
            } else if (result.isError) {
                console.error(`Transaction error: ${result.toHuman()}`);
                reject(result);
            }
        });
    });
}

// Ruta para obtener las cuentas asociadas a un dni
app.get('/get_accounts/:dni', async (req, res) => {
    const { dni } = req.params;
    const { requestNumber, groupID, totalTransactions } = req.query;

    res.locals.requestNumber = requestNumber || 'N/A';
    res.locals.groupID = groupID || 'N/A';
    res.locals.totalTransactions = totalTransactions || 'N/A';

    try {
        console.log(`Attempting to fetch accounts for DNI: ${dni}`);

        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 10000000000),
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });

        console.log('Querying contract...');
        const { result, output } = await contract.query.getAccounts(api.createType('AccountId', CONTRACT_ADDRESS), { value: 0, gasLimit }, dni);

        console.log('Query result:', result.toHuman());
        console.log('Query output:', output ? output.toHuman() : 'No output');

        if (result.isOk) {
            res.locals.transactionSuccess = true;
            if (output) {
                const accounts = output.toJSON();
                console.log('Parsed accounts:', accounts);
                
                if (accounts && accounts.ok && Array.isArray(accounts.ok) && accounts.ok.length > 0) {
                    console.log(`Found ${accounts.ok.length} accounts for DNI ${dni}`);
                    res.json(accounts.ok);
                } else {
                    console.log(`No accounts found for DNI ${dni}`);
                    res.status(404).send(`No accounts found for dni ${dni}`);
                }
            } else {
                console.log('Query successful but no output returned');
                res.status(404).send(`No accounts found for dni ${dni}`);
            }
        } else {
            res.locals.transactionSuccess = false;
            console.error('Contract call failed:', result.asErr.toHuman());
            res.status(500).send('Error fetching accounts: Contract call failed');
        }
    } catch (error) {
        res.locals.transactionSuccess = false;
        console.error(`Error fetching accounts for dni ${dni}:`, error);
        res.status(500).send(`Error fetching accounts: ${error.message}`);
    }
});

// Modificar el endpoint para crear un usuario
app.post('/create_user', async (req, res) => {
    const { name, lastname, dni, email, role } = req.body;
    const newAccount = createNewAccount(); // Genera una nueva cuenta

    const userInfo = {
        name: name,
        lastname: lastname,
        dni: dni,
        email: email
    };

    try {
        const keyring = new Keyring({ type: 'sr25519' });
        alice = keyring.addFromUri('//Alice'); // Usar la cuenta de Alice

        // Definir un límite de gas adecuado
        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 20000000000),
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });

        // Transferir fondos a la nueva cuenta
        await transferFunds(alice, newAccount.address, 1000000000000);

        // Añadir el usuario con el gasLimit
        await addUser(alice, newAccount, userInfo, role, gasLimit, res);

        res.status(200).send(`User and role added successfully`);
    } catch (error) {
        res.status(500).send(`Error adding user: ${error.message}`);
    }
});

// Modificar el endpoint para crear un usuario con una dirección existente
app.post('/create_user_with_existing_address', async (req, res) => {
    const { address, name, lastname, dni, email, role } = req.body;

    // Verify that the provided address is valid
    const keyring = new Keyring({ type: 'sr25519' });
    let userAddress;
    try {
        userAddress = keyring.encodeAddress(address);
    } catch (error) {
        return res.status(400).send('Invalid address provided');
    }

    const userInfo = {
        name: name,
        lastname: lastname,
        dni: dni,
        email: email
    };

    try {
        alice = keyring.addFromUri('//Alice'); // Use Alice's account to sign the transaction

        // Definir un límite de gas adecuado
        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 20000000000),
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });

        // Transfer funds to the user's address using transferKeepAlive
        await transferFunds(alice, userAddress, 1000000000000);

        // Wait a bit to ensure the transfer has been completed
        //await new Promise(resolve => setTimeout(resolve, 6000));

        // Add the user and their information to the contract with gasLimit
        await addUser(alice, userAddress, userInfo, role, gasLimit, res);

        res.status(200).send(`User created with address ${userAddress}`);
    } catch (error) {
        console.error(`Error creating user with address ${userAddress}: ${error}`);
        res.status(500).send(`Error creating user: ${error.message}`);
    }
});

// Endpoint para obtener el rol de un usuario
app.get('/role/:publicAddress', async (req, res) => {
    const { publicAddress } = req.params;
    const { requestNumber, groupID, totalTransactions, testType } = req.query;

    res.locals.requestNumber = requestNumber || 'N/A';
    res.locals.groupID = groupID || 'N/A';
    res.locals.totalTransactions = totalTransactions || 'N/A';
    res.locals.testType = testType || 'N/A'; // Asegurar que testType se almacene correctamente

    try {
        const keyring = new Keyring({ type: 'sr25519' });
        let accountId;
        try {
            accountId = keyring.decodeAddress(publicAddress);
        } catch (e) {
            console.error("Failed to decode address:", e);
            return res.status(400).send(`Invalid public address: ${publicAddress}`);
        }

        console.log("Decoded Account ID:", accountId);

        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 10000000000),
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });
        const { output } = await contract.query.getRole(accountId, { value: 0, gasLimit }, accountId);

        console.log("Contract query response:", output ? output.toHuman() : "No output");

        if (!output || output.isNone) {
            res.locals.transactionSuccess = false;
            return res.status(404).send(`Role not found for account ${publicAddress}`);
        }

        // Verifica si output tiene la propiedad value y maneja Option<u8>
        if (output && output.value !== undefined) {
            const role = output.value !== null ? output.value.toString() : 'None';
            res.locals.transactionSuccess = true;
            res.status(200).send(`Role for account ${publicAddress}: ${role}`);
        } else {
            res.locals.transactionSuccess = false;
            res.status(500).send('Error fetching role: Invalid output format');
        }
    } catch (error) {
        res.locals.transactionSuccess = false;
        console.error("Error fetching role:", error);
        res.status(500).send(`Error fetching role: ${error.message}`);
    }
});

// Alias para obtener el rol de un usuario usando /get_role/:publicAddress
app.get('/get_role/:publicAddress', async (req, res) => {
    // Imprimir los parámetros recibidos
    console.log('Parámetros recibidos en /get_role:', req.params);
    
    // Reutilizar el manejador de la ruta /role/:publicAddress
    req.url = `/role/${req.params.publicAddress}`;
    return app._router.handle(req, res, () => {});
});

// Endpoint para obtener la dirección de Alice
app.get('/alice_account_id', async (req, res) => {
    const keyring = new Keyring({ type: 'sr25519' });
    alice = keyring.addFromUri('//Alice');
    res.status(200).send(`Alice's account: ${alice.address}`);
});

// Modificar la función executeContractAndGetGas para usar el nonce
async function executeContractAndGetGas(contract, signer, res, ...params) {
    try {
        updateTransactionCount(); // Actualizar el contador de transacciones
        const tip = getTip();
        const nonce = await getCurrentNonce(signer.address); // Obtener el nonce actual
        // Definir un límite de gas alto para asegurar la ejecución (sin estimación previa)
        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 20000000000), // Ajusta este valor según sea necesario
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });

        // Inicializar refTime y proofSize fuera del contexto de los eventos
        let refTime = null;
        let proofSize = null;

        // Llamada al método del contrato
        const tx = contract.tx.addUser(
            { value: 0, gasLimit }, // Opciones de la transacción
            ...params // Parámetros del método
        );

        // Enviar la transacción y esperar a la finalización
        return new Promise((resolve, reject) => {
            tx.signAndSend(signer, { nonce, tip }, (result) => { // Incluir nonce y tip
                if (result.status.isFinalized) {
                    //console.log('Transacción finalizada en bloque:', result.status.asFinalized);

                    // Iterar sobre los eventos para encontrar el peso (gas) consumido
                    result.events.forEach(({ event: { data, method, section } }) => {
                        console.log(`Event: ${section}.${method} - ${JSON.stringify(data.toHuman())}`);

                        if (section === 'system' && method === 'ExtrinsicSuccess') {
                            // Obtener el gas computacional (refTime) y el proofSize del evento ExtrinsicSuccess
                            if (data && data.length > 0 && data[0].weight) {
                                refTime = data[0].weight.refTime;
                                proofSize = data[0].weight.proofSize;
                                console.log(`Gas (refTime) consumido: ${refTime}`);
                                console.log(`ProofSize consumido: ${proofSize}`);
                            }
                        }
                    });

                    // Guardar refTime, proofSize, tip y el estado de éxito en res.locals
                    res.locals.refTime = refTime || 'N/A'; // Si no se encuentra, asignar 'N/A'
                    res.locals.proofSize = proofSize || 'N/A'; // Si no se encuentra, asignar 'N/A'
                    res.locals.tip = tip.toString(); // Guardar el valor del tip
                    res.locals.transactionSuccess = true; // Transacción exitosa
                    res.locals.transactionCount = transactionCount; // Guardamos el contador de la transacción

                    resolve({
                        blockHash: result.status.asFinalized.toString(),
                        gasUsed: refTime ? refTime.toHuman() : 'No se encontró el consumo de gas',
                        proofSizeUsed: proofSize ? proofSize.toHuman() : 'No se encontró el consumo de proofSize',
                        tip: tip.toString() // Retorna el valor del tip
                    });
                } else if (result.isError) {
                    console.error('Error en la transacción:', result);

                    // Guardar el estado de fallo en res.locals
                    res.locals.transactionSuccess = false; // Transacción fallida
                    res.locals.refTime = 0; // Gas 0 cuando falla la transacción
                    res.locals.proofSize = 0; // proofSize 0 cuando falla la transacción
                    res.locals.tip = '0'; // Tip 0 cuando falla la transacción

                    reject(new Error('Error en la transacción.'));
                }
            });
        });

    } catch (error) {
        console.error(`Error al ejecutar la transacción: ${error.message}`);
        res.locals.transactionSuccess = false; // Transacción fallida
        res.locals.refTime = 0; // Gas 0 cuando falla la transacción
        res.locals.proofSize = 0; // proofSize 0 cuando falla la transacción
        res.locals.tip = '0'; // Tip 0 cuando falla la transacción
        throw error;
    }
}

// Ruta POST para crear un usuario usando la función addUser con gas dinámico
app.post('/create_user_with_dynamic_gas', async (req, res) => {
    // Imprimir los datos recibidos del batch
    console.log('Datos recibidos en /create_user_with_dynamic_gas:', req.body);
    
    const { name, lastname, dni, email, role, groupID, totalTransactions, requestNumber, testType } = req.body;

    try {
        const keyring = new Keyring({ type: 'sr25519' });
        alice = keyring.addFromUri('//Alice'); // Usar la cuenta de Alice para firmar la transacción

        const newAccount = createNewAccount(); // Genera una nueva cuenta

        const userInfo = {
            name: name,
            lastname: lastname,
            dni: dni,
            email: email
        };

        // Transferir fondos a la nueva cuenta y esperar hasta que la transacción sea finalizada
        await transferFunds(alice, newAccount.address, 1000000000000);

        // Definir un límite de gas alto para la transacción (ajusta según tu necesidad)
        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 20000000000), // Ajusta este valor según lo necesario
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });

        // Ejecutar la transacción del contrato (addUser) y guardar el gas consumido y tip
        await addUser(alice, newAccount, userInfo, role, gasLimit, res, testType);
        
        // Guardar el Account ID en 'account_ids.txt'
        fs.appendFileSync(ACCOUNT_IDS_FILE, `${newAccount.address}\n`, 'utf8');

        // Responder con éxito
        res.status(200).json({
            message: 'Usuario creado con éxito',
            blockHash: res.locals.blockHash,
            gasUsed: res.locals.refTime,
            proofSize: res.locals.proofSize,
            tip: res.locals.tip
        });

    } catch (error) {
        console.error('Error al crear el usuario:', error);
        res.status(500).json({ error: `Error al crear el usuario: ${error.message}` });
    }
});

// Endpoint para verificar si un permiso existe entre dos usuarios
app.get('/has_permission/:granter/:grantee', async (req, res) => {
    const { granter, grantee } = req.params;
    const { requestNumber, groupID, totalTransactions, testType } = req.query;

    // Validar que ambos parámetros estén presentes
    if (!granter || !grantee) {
        res.locals.transactionSuccess = false;
        return res.status(400).send('Parámetros "granter" y "grantee" son requeridos.');
    }

    res.locals.requestNumber = requestNumber || 'N/A';
    res.locals.groupID = groupID || 'N/A';
    res.locals.totalTransactions = totalTransactions || 'N/A';
    res.locals.testType = testType || 'N/A'; // Asegurar que testType se almacene correctamente

    try {
        const granterAccountId = api.createType('AccountId', granter);
        const granteeAccountId = api.createType('AccountId', grantee);

        const gasLimit = api.registry.createType('WeightV2', {
            refTime: api.registry.createType('Compact<u64>', 10000000000),
            proofSize: api.registry.createType('Compact<u64>', 10000000)
        });

        const { output } = await contract.query.hasPermission(granterAccountId, { value: 0, gasLimit }, granterAccountId, granteeAccountId);

        if (output) {
            res.locals.transactionSuccess = true;
            const hasPermission = output.toHuman();
            res.status(200).json({ hasPermission });
        } else {
            res.locals.transactionSuccess = false;
            res.status(404).send('No se pudo obtener el permiso');
        }

    } catch (error) {
        res.locals.transactionSuccess = false;
        console.error('Error al consultar el permiso:', error);
        res.status(500).send(`Error al consultar el permiso: ${error.message}`);
    }
});

// Nuevo endpoint para otorgar permisos
app.post('/grant_permission', async (req, res) => {
    // Imprimir los datos recibidos para otorgar permisos
    console.log('Datos recibidos en /grant_permission:', req.body);
    
    const { granter, grantee, requestNumber, groupID, totalTransactions } = req.body;

    res.locals.requestNumber = requestNumber || 'N/A';
    res.locals.groupID = groupID || 'N/A';
    res.locals.totalTransactions = totalTransactions || 'N/A';

    try {
        // Implementar la lógica para otorgar permisos
        // ...código para otorgar permisos...
        res.locals.transactionSuccess = true;
        res.status(200).send('Permiso otorgado exitosamente');
    } catch (error) {
        res.locals.transactionSuccess = false;
        res.status(500).send(`Error al otorgar el permiso: ${error.message}`);
    }
});

app.post('/verify_hyperledger_user', async (req, res) => {
    const { org, dni, role } = req.body;

    try {
        // Realizar solicitud al servidor de Hyperledger Fabric
        const response = await axios.post('`${FABRIC_SERVER_URL}/verify_hyperledger_user', {
            org,
            dni,
            role,
        });

        res.status(200).json({
            message: 'Usuario verificado exitosamente en Hyperledger Fabric.',
            data: response.data,
        });
    } catch (error) {
        res.status(500).json({
            error: `Error verificando usuario en Hyperledger Fabric: ${error.message}`,
        });
    }
});

// Endpoint para leer el HME desde Polkadot
app.post('/read_hme', async (req, res) => {
    const { org, readerDni, patientDni } = req.body;

    // Validar los datos de entrada
    if (!org || !readerDni || !patientDni) {
        return res.status(400).json({ error: 'Organización, DNI del lector y del paciente son requeridos.' });
    }

    try {
        // Enviar solicitud al servidor de Hyperledger Fabric
        const response = await axios.post(`${FABRIC_SERVER_URL}/read_hme`, {
            org,
            readerDni,
            patientDni,
        });

        // Responder con los datos obtenidos
        res.status(200).json({
            message: 'HME leído exitosamente desde Hyperledger Fabric.',
            data: response.data,
        });
    } catch (error) {
        console.error(`Error leyendo HME desde Hyperledger Fabric: ${error.message}`);
        res.status(500).json({
            error: `Error leyendo HME desde Hyperledger Fabric: ${error.message}`,
        });
    }
});

// Iniciar el servidor
init().then(() => {
    const host = process.env.HOST || '0.0.0.0';
    app.listen(port, host, () => {
      console.log(`API listening at http://${host}:${port}`);
      if (ENABLE_PERFORMANCE_MONITORING) {
        console.log(`Performance monitoring enabled. Logs will be written to ${LOG_FILE_PATH}`);
      }
    });
}).catch((error) => {
    console.error(`Failed to initialize API: ${error.message}`);
});