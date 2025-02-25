// account_functions.js

const { ApiPromise, Keyring } = require('@polkadot/api');
const { mnemonicGenerate } = require('@polkadot/util-crypto');
const { getTip } = require('./tip_manager'); // Importar el módulo de gestión de tips

// Contador de transacciones
let transactionCount = 0;

// Función para actualizar el contador de transacciones
function updateTransactionCount() {
    transactionCount += 1;
    console.log(`Transaction count updated: ${transactionCount}`);
}

// Función para crear una nueva cuenta y obtener su dirección y mnemonic
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
async function transferFunds(api, sender, recipient, amount) {
    const transfer = api.tx.balances.transferKeepAlive(recipient, amount);

    return new Promise((resolve, reject) => {
        transfer.signAndSend(sender, { tip: getTip() }, (result) => {
            if (result.status.isInBlock) {
                console.log(`Transferencia incluida en el bloque: ${result.status.asInBlock}`);
            }
            if (result.status.isFinalized) {
                console.log(`Transferencia finalizada en el bloque: ${result.status.asFinalized}`);
                resolve(result);
            }
            if (result.isError) {
                console.error('Error en la transferencia:', result);
                reject(new Error('Error en la transferencia.'));
            }
        }).catch((error) => {
            reject(new Error(`Error en la transferencia: ${error.message}`));
        });
    });
}

// Función para añadir un usuario en el contrato
async function addUser(api, contract, alice, newAccount, userInfo, role, gasLimit) {
    const addUserTx = contract.tx.addUser({ value: 0, gasLimit }, newAccount.address, userInfo, role);

    return new Promise((resolve, reject) => {
        addUserTx.signAndSend(alice, { tip: getTip() }, ({ events = [], status }) => {
            if (status.isInBlock) {
                console.log(`Transaction included at blockHash ${status.asInBlock}`);
                events.forEach(({ event: { data, method, section } }) => {
                    if (section === 'system' && method === 'ExtrinsicFailed') {
                        const [dispatchError] = data;
                        if (dispatchError.isModule) {
                            const decoded = api.registry.findMetaError(dispatchError.asModule);
                            console.error(`Error: ${decoded.section}.${decoded.name}`);
                        } else {
                            console.error(`Error: ${dispatchError.toString()}`);
                        }
                    }
                });
            } else if (status.isFinalized) {
                console.log(`Transaction finalized at blockHash ${status.asFinalized}`);
                resolve(status);
            }
        }).catch(error => {
            console.error(`Transaction failed: ${error}`);
            reject(error);
        });
    });
}

// Función para obtener cuentas por DNI
async function getAccountsByDni(api, contract, contractAddress, dni) {
    const gasLimit = api.registry.createType('WeightV2', {
        refTime: api.registry.createType('Compact<u64>', 10000000000),
        proofSize: api.registry.createType('Compact<u64>', 10000000)
    });
    console.log('Querying contract...');
    const { result, output } = await contract.query.getAccounts(api.createType('AccountId', contractAddress), { value: 0, gasLimit }, dni);

    console.log('Query result:', result.toHuman());
    console.log('Query output:', output ? output.toHuman() : 'No output');

    if (result.isOk) {
        if (output) {
            const accounts = output.toJSON();
            console.log('Parsed accounts:', accounts);

            if (accounts && accounts.ok && Array.isArray(accounts.ok) && accounts.ok.length > 0) {
                console.log(`Found ${accounts.ok.length} accounts for DNI ${dni}`);
                return accounts.ok;
            } else {
                console.log(`No accounts found for DNI ${dni}`);
                throw new Error(`No accounts found for dni ${dni}`);
            }
        } else {
            console.log('Query successful but no output returned');
            throw new Error(`No accounts found for dni ${dni}`);
        }
    } else {
        console.error('Contract call failed:', result.asErr.toHuman());
        throw new Error('Error fetching accounts: Contract call failed');
    }
}

// Función para obtener el rol de un usuario por dirección pública
async function getUserRole(api, contract, publicAddress) {
    const keyring = new Keyring({ type: 'sr25519' });
    let accountId;
    try {
        accountId = keyring.decodeAddress(publicAddress);
    } catch (e) {
        console.error("Failed to decode address:", e);
        throw new Error(`Invalid public address: ${publicAddress}`);
    }

    console.log("Decoded Account ID:", accountId);

    const gasLimit = api.registry.createType('WeightV2', {
        refTime: api.registry.createType('Compact<u64>', 10000000000),
        proofSize: api.registry.createType('Compact<u64>', 10000000)
    });
    const { output } = await contract.query.getRole(accountId, { value: 0, gasLimit }, accountId);

    console.log("Contract query response:", output ? output.toHuman() : "No output");

    if (!output || output.isNone) {
        throw new Error(`Role not found for account ${publicAddress}`);
    }

    // Verifica si output tiene la propiedad value y maneja Option<u8>
    if (output && output.value !== undefined) {
        return output.value !== null ? output.value.toString() : 'None';
    } else {
        throw new Error('Error fetching role: Invalid output format');
    }
}

// Función para ejecutar el contrato y obtener el gas consumido después de la ejecución
async function executeContractAndGetGas(contract, signer, res, ...params) {
    try {
        updateTransactionCount(); // Actualizar el contador de transacciones

        // Definir un límite de gas alto para asegurar la ejecución (sin estimación previa)
        const gasLimit = contract.api.registry.createType('WeightV2', {
            refTime: contract.api.registry.createType('Compact<u64>', 20000000000), // Ajusta este valor según lo necesario
            proofSize: contract.api.registry.createType('Compact<u64>', 10000000)
        });

        let refTime = null;

        // Llamada directa al método addUser del contrato
        const tx = contract.tx.addUser(
            { value: 0, gasLimit }, // Asigna un gas límite alto
            ...params // Los parámetros del método
        );

        // Enviar la transacción y esperar a la finalización
        return new Promise((resolve, reject) => {
            tx.signAndSend(signer, (result) => {
                if (result.status.isFinalized) {
                    //console.log('Transacción finalizada en bloque:', result.status.asFinalized);

                    // Iterar sobre los eventos para encontrar el peso (gas) consumido
                    result.events.forEach(({ event: { data, method, section } }) => {
                        console.log(`Event: ${section}.${method} - ${JSON.stringify(data.toHuman())}`);

                        if (section === 'system' && method === 'ExtrinsicSuccess') {
                            // Obtener el gas computacional (refTime) del evento ExtrinsicSuccess
                            if (data && data.length > 0 && data[0].weight) {
                                refTime = data[0].weight.refTime;
                                console.log(`Gas (refTime) consumido: ${refTime}`);
                            }
                        }
                    });

                    // Guardar refTime y el estado de éxito en res.locals
                    res.locals.refTime = refTime || 'N/A'; // Si no se encuentra, asignar 'N/A'
                    res.locals.transactionSuccess = true; // Transacción exitosa
                    res.locals.transactionCount = transactionCount; // Guardamos el contador de la transacción

                    resolve({
                        blockHash: result.status.asFinalized.toString(),
                        gasUsed: refTime ? refTime.toHuman() : 'No se encontró el consumo de gas'
                    });
                } else if (result.isError) {
                    console.error('Error en la transacción:', result);

                    // Guardar el estado de fallo en res.locals
                    res.locals.transactionSuccess = false; // Transacción fallida
                    res.locals.refTime = 0; // Gas 0 cuando falla la transacción

                    reject(new Error('Error en la transacción.'));
                }
            });
        });

    } catch (error) {
        console.error(`Error al ejecutar la transacción: ${error.message}`);
        res.locals.transactionSuccess = false; // Transacción fallida
        res.locals.refTime = 0; // Gas 0 cuando falla la transacción
        throw error;
    }
}

module.exports = {
    createNewAccount,
    transferFunds,
    addUser,
    getAccountsByDni,
    getUserRole,
    executeContractAndGetGas,
    updateTransactionCount // Exportar la función de contador
};
