// logging_middleware.js

const fs = require('fs');
const path = require('path');
const os = require('os');
require('dotenv').config();

// Rutas para los archivos de logs
const LOG_FILE_PATH = path.join(__dirname, 'performance_log.txt');
const logFileJsonPath = path.join(__dirname, 'performance_log.json');
let fileExists = fs.existsSync(logFileJsonPath);

// Función para obtener el uso de sistema actual (CPU y RAM)
function getSystemUsage() {
    const cpus = os.cpus();

    let totalIdle = 0;
    let totalTick = 0;

    cpus.forEach((core) => {
        for (const type in core.times) {
            totalTick += core.times[type];
        }
        totalIdle += core.times.idle;
    });

    const idle = totalIdle / cpus.length;
    const total = totalTick / cpus.length;
    const usage = 100 - Math.round((100 * idle) / total);

    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memUsage = (usedMem / totalMem) * 100;

    return { cpuUsage: usage, memUsage };
}

// Función para calcular la longitud total de los parámetros
function getParamsLength(req) {
    let length = 0;

    // Longitud de parámetros del cuerpo (body)
    if (req.body && typeof req.body === 'object') {
        length += JSON.stringify(req.body).length;
    }

    return length;
}

// Middleware para medir la duración de la solicitud y registrar logs en formato txt
function logRequestToTxt(req, res, next) {
    const startTime = Date.now();
    const { cpuUsage: startCpu, memUsage: startMem } = getSystemUsage();
    const paramsLength = getParamsLength(req);
    
    // Asignar requestNumber desde req.query o req.body
    res.locals.requestNumber = req.query.requestNumber || req.body.requestNumber || 'N/A';

    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const { cpuUsage: endCpu, memUsage: endMem } = getSystemUsage();
        const groupID = req.body.groupID || req.query.groupID || 'N/A';
        const totalTransactions = req.body.totalTransactions || req.query.totalTransactions || 'N/A';
        const requestNumber = res.locals.requestNumber || 'N/A';
        const testType = req.body.testType || req.query.testType || 'N/A';
        const route = `${req.method} ${req.originalUrl.split('?')[0]}`;

        const logEntry = `
        Time: ${new Date().toISOString()}
        Request Number: ${requestNumber}
        GroupID: ${groupID}
        Total Transactions: ${totalTransactions}
        Route: ${route}
        Method: ${req.method}
        RefTime (Gas Computacional): ${res.locals.refTime || 'N/A'}
        ProofSize: ${res.locals.proofSize || 'N/A'}
        Tip: ${res.locals.tip || 'N/A'}
        Duration: ${duration} ms
        CPU Usage (start): ${startCpu.toFixed(2)}%
        CPU Usage (end): ${endCpu.toFixed(2)}%
        RAM Usage (start): ${startMem.toFixed(2)}%
        RAM Usage (end): ${endMem.toFixed(2)}%
        Transaction Success: ${res.locals.transactionSuccess ? 'Yes' : 'No'}
        Parameters Length: ${paramsLength}
        Test Type: ${testType}
        ---
        `;

        // Escribir el log en archivo txt
        fs.appendFile(LOG_FILE_PATH, logEntry, (err) => {
            if (err) throw new Error(`Error al escribir en el log: ${err.message}`);
        });
    });

    next();
}

// Middleware para medir la duración de la solicitud y registrar logs en formato JSON
function logRequestToJson(req, res, next) {
    const startTime = Date.now();
    const { cpuUsage: startCpu, memUsage: startMem } = getSystemUsage();
    const paramsLength = getParamsLength(req);
    
    // Asignar requestNumber desde req.query o req.body
    res.locals.requestNumber = req.query.requestNumber || req.body.requestNumber || 'N/A';

    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const { cpuUsage: endCpu, memUsage: endMem } = getSystemUsage();
        const groupID = req.body.groupID || req.query.groupID || 'N/A';
        const totalTransactions = req.body.totalTransactions || req.query.totalTransactions || 'N/A';
        const requestNumber = res.locals.requestNumber || 'N/A';
        const testType = req.body.testType || req.query.testType || 'N/A';
        const route = `${req.method} ${req.originalUrl.split('?')[0]}`;

        const logEntry = {
            time: new Date().toISOString(),
            requestNumber: requestNumber,
            groupID: groupID,
            totalTransactions: totalTransactions,
            route: route,
            method: req.method,
            refTime: res.locals.refTime || 'N/A',
            proofSize: res.locals.proofSize || 'N/A',
            tip: res.locals.tip || 'N/A',
            duration: `${duration} ms`,
            cpuUsageStart: `${startCpu.toFixed(2)}%`,
            cpuUsageEnd: `${endCpu.toFixed(2)}%`,
            ramUsageStart: `${startMem.toFixed(2)}%`,
            ramUsageEnd: `${endMem.toFixed(2)}%`,
            transactionSuccess: res.locals.transactionSuccess ? 'Yes' : 'No',
            parametersLength: paramsLength,
            testType: testType
        };

        const logEntryString = JSON.stringify(logEntry);

        if (!fileExists) {
            try {
                const initialContent = `[${logEntryString}]`;
                fs.writeFileSync(logFileJsonPath, initialContent);
                fileExists = true;
            } catch (err) {
                console.error(`Error al crear el archivo de log JSON: ${err.message}`);
            }
        } else {
            try {
                fs.readFile(logFileJsonPath, 'utf8', (err, data) => {
                    if (err) return console.error(`Error al leer el archivo de log JSON: ${err.message}`);

                    let newData = data.trim();

                    if (newData.length === 0 || newData === '[]') {
                        newData = `[${logEntryString}]`;
                    } else {
                        newData = newData.slice(0, -1);
                        newData += `,${logEntryString}]`;
                    }

                    fs.writeFile(logFileJsonPath, newData, (err) => {
                        if (err) return console.error(`Error al escribir en el archivo de log JSON: ${err.message}`);
                    });
                });
            } catch (err) {
                console.error(`Error al actualizar el archivo de log JSON: ${err.message}`);
            }
        }
    });

    next();
}

module.exports = {
    logRequestToTxt,
    logRequestToJson,
    getSystemUsage
};
