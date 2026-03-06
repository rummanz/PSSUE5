// Copyright Epic Games, Inc. All Rights Reserved.
var enableRedirectionLinks = true;
var enableRESTAPI = true;

const defaultConfig = {
	// The port clients connect to the matchmaking service over HTTP
	HttpPort: 90,
	UseHTTPS: false,
	// The matchmaking port the signaling service connects to the matchmaker
	MatchmakerPort: 9999,

	// Log to file
	LogToFile: true,

	EnableWebserver: true,

	// GameManager API fan-out settings
	GameManagerPort: 8000,
	GameManagerTimeoutMs: 8000,
};

// Similar to the Signaling Server (SS) code, load in a config.json file for the MM parameters
const argv = require('yargs').argv;

var configFile = (typeof argv.configFile != 'undefined') ? argv.configFile.toString() : 'config.json';
console.log(`configFile ${configFile}`);
const config = require('./modules/config.js').init(configFile, defaultConfig);
console.log("Config: " + JSON.stringify(config, null, '\t'));

const express = require('express');
var cors = require('cors');
const app = express();
const http = require('http').Server(app);
const fs = require('fs');
const path = require('path');
const logging = require('./modules/logging.js');
logging.RegisterConsoleLogger();

if (config.LogToFile) {
	logging.RegisterFileLogger('./logs');
}

// A list of all the Cirrus server which are connected to the Matchmaker.
var cirrusServers = new Map();

//
// Parse command line.
//

if (typeof argv.HttpPort != 'undefined') {
	config.HttpPort = argv.HttpPort;
}
if (typeof argv.MatchmakerPort != 'undefined') {
	config.MatchmakerPort = argv.MatchmakerPort;
}

http.listen(config.HttpPort, () => {
	console.log('HTTP listening on *:' + config.HttpPort);
});


if (config.UseHTTPS) {
	//HTTPS certificate details
	const options = {
		key: fs.readFileSync(path.join(__dirname, './certificates/client-key.pem')),
		cert: fs.readFileSync(path.join(__dirname, './certificates/client-cert.pem'))
	};

	var https = require('https').Server(options, app);

	//Setup http -> https redirect
	console.log('Redirecting http->https');
	app.use(function (req, res, next) {
		if (!req.secure) {
			if (req.get('Host')) {
				var hostAddressParts = req.get('Host').split(':');
				var hostAddress = hostAddressParts[0];
				return res.redirect(['https://', hostAddress, req.originalUrl].join(''));
			} else {
				console.error(`unable to get host name from header. Requestor ${req.ip}, url path: '${req.originalUrl}', available headers ${JSON.stringify(req.headers)}`);
				return res.status(400).send('Bad Request');
			}
		}
		next();
	});

	https.listen(443, function () {
		console.log('Https listening on 443');
	});
}

let htmlDirectory = 'html/sample'
if (config.EnableWebserver) {
	// Setup folders

	if (fs.existsSync('html/custom')) {
		app.use(express.static(path.join(__dirname, '/html/custom')))
		htmlDirectory = 'html/custom'
	} else {
		app.use(express.static(path.join(__dirname, '/html/sample')))
	}
}

// No servers are available so send some simple JavaScript to the client to make
// it retry after a short period of time.
function sendRetryResponse(res) {
	// find check if a custom template should be used or the sample one
	let html = fs.readFileSync(`${htmlDirectory}/queue/queue.html`, { encoding: 'utf8' })
	html = html.replace(/\$\{cirrusServers\.size\}/gm, cirrusServers.size)

	res.setHeader('content-type', 'text/html')
	res.send(html)
}

// Get a Cirrus server if there is one available which has no clients connected.
function getAvailableCirrusServer() {
	for (cirrusServer of cirrusServers.values()) {
		if (cirrusServer.numConnectedClients === 0 && cirrusServer.ready === true) {

			// Check if we had at least 10 seconds since the last redirect, avoiding the 
			// chance of redirecting 2+ users to the same SS before they click Play.
			// In other words, give the user 10 seconds to click play button the claim the server.
			if (cirrusServer.hasOwnProperty('lastRedirect')) {
				if (((Date.now() - cirrusServer.lastRedirect) / 1000) < 10)
					continue;
			}
			cirrusServer.lastRedirect = Date.now();

			return cirrusServer;
		}
	}

	console.log('WARNING: No empty Cirrus servers are available');
	return undefined;
}

if (enableRESTAPI) {
	// Handle REST signalling server only request.
	app.options('/signallingserver', cors())
	app.get('/signallingserver', cors(), (req, res) => {
		cirrusServer = getAvailableCirrusServer();
		if (cirrusServer != undefined) {
			res.json({ signallingServer: `${cirrusServer.address}:${cirrusServer.port}` });
			console.log(`Returning ${cirrusServer.address}:${cirrusServer.port}`);
		} else {
			res.json({ signallingServer: '', error: 'No signalling servers available' });
		}
	});

	// Handle REST status request
	app.get('/api/status', cors(), (req, res) => {
		res.json({ servers: getStatusServers() });
	});

	// Game Management APIs
	const multer = require('multer');
	const upload = multer({ dest: 'uploads/' });
	const axios = require('axios');
	const fs = require('fs');
	const FormData = require('form-data');
	const gameManagerPort = config.GameManagerPort || 8000;
	const gameManagerTimeoutMs = config.GameManagerTimeoutMs || 8000;

	const gameManagerClient = axios.create({
		timeout: gameManagerTimeoutMs,
		validateStatus: () => true
	});

	function getStatusServers() {
		let servers = [];
		for (const cirrusServer of cirrusServers.values()) {
			servers.push({
				address: cirrusServer.address,
				port: cirrusServer.port,
				ready: cirrusServer.ready,
				numConnectedClients: cirrusServer.numConnectedClients,
				lastPingReceived: cirrusServer.lastPingReceived
			});
		}
		return servers;
	}

	function getUniqueAddresses() {
		const uniqueAddresses = new Set();
		for (const server of cirrusServers.values()) {
			uniqueAddresses.add(server.address);
		}
		return [...uniqueAddresses];
	}

	async function requestGameManager(ip, endpoint, method, data = null, file = null) {
		const url = `http://${ip}:${gameManagerPort}${endpoint}`;
		const startedAt = Date.now();

		try {
			let response;
			if (file) {
				const form = new FormData();
				form.append('file', fs.createReadStream(file.path), file.originalname);
				response = await gameManagerClient.post(url, form, {
					headers: { ...form.getHeaders() }
				});
			} else if (method === 'POST') {
				response = await gameManagerClient.post(url, data || {});
			} else {
				response = await gameManagerClient.get(url);
			}

			const success = response.status >= 200 && response.status < 300;

			if (!success) {
				console.error(`GameManager request failed ${url} -> HTTP ${response.status}`);
			}

			return {
				ip: ip,
				status: success ? 'success' : 'failed',
				httpStatus: response.status,
				elapsedMs: Date.now() - startedAt,
				data: response.data,
				error: success ? undefined : `HTTP ${response.status}`
			};
		} catch (error) {
			const errorMessage = error.code ? `${error.code}: ${error.message}` : error.message;
			console.error(`Failed to contact ${url}: ${errorMessage}`);
			return {
				ip: ip,
				status: 'failed',
				elapsedMs: Date.now() - startedAt,
				error: errorMessage
			};
		}
	}

	// Helper to broadcast to all connected Game VMs (Agent Port 8000)
	async function broadcastToGames(endpoint, method, data = null, file = null) {
		const targets = getUniqueAddresses();
		const requests = targets.map((ip) => requestGameManager(ip, endpoint, method, data, file));
		return Promise.all(requests);
	}

	app.get('/api/game/status', cors(), async (req, res) => {
		console.log('Fetching combined game status...');
		const [versionResults, statsResults] = await Promise.all([
			broadcastToGames('/version', 'GET'),
			broadcastToGames('/stats', 'GET')
		]);

		const versionByIp = new Map();
		for (const item of versionResults) {
			versionByIp.set(item.ip, item);
		}

		const statsByIp = new Map();
		for (const item of statsResults) {
			statsByIp.set(item.ip, item);
		}

		const servers = getStatusServers().map((server) => {
			const versionResult = versionByIp.get(server.address);
			const statsResult = statsByIp.get(server.address);

			return {
				...server,
				version: versionResult?.data?.version || 'Unknown',
				pid: versionResult?.data?.pid || null,
				is_running: versionResult?.data?.is_running || false,
				stats: statsResult?.status === 'success' ? statsResult.data : null,
				api: {
					version: versionResult ? {
						status: versionResult.status,
						error: versionResult.error,
						httpStatus: versionResult.httpStatus,
						elapsedMs: versionResult.elapsedMs
					} : null,
					stats: statsResult ? {
						status: statsResult.status,
						error: statsResult.error,
						httpStatus: statsResult.httpStatus,
						elapsedMs: statsResult.elapsedMs
					} : null
				}
			};
		});

		res.json({
			servers,
			versionResults,
			statsResults,
			timeoutMs: gameManagerTimeoutMs
		});
	});

	app.options('/api/game/upload', cors()); // Enable pre-flight request for upload
	app.post('/api/game/upload', cors(), upload.single('file'), async (req, res) => {
		if (!req.file) {
			return res.status(400).send('No file uploaded.');
		}
		console.log(`Received file ${req.file.originalname}, broadcasting upload...`);

		const results = await broadcastToGames('/upload', 'POST', null, req.file);

		// Cleanup temp file
		fs.unlink(req.file.path, (err) => {
			if (err) console.error("Error deleting temp file:", err);
		});

		res.json({ results: results });
	});

	app.post('/api/game/broadcast', cors(), express.json(), async (req, res) => {
		const { command } = req.body;
		if (!command || !['start', 'stop'].includes(command)) {
			return res.status(400).send('Invalid command');
		}

		console.log(`Broadcasting command: ${command}`);
		const results = await broadcastToGames(`/${command}`, 'POST');
		res.json({ results: results });
	});

	app.post('/api/game/server/:serverAddress/:command', cors(), async (req, res) => {
		const serverAddress = decodeURIComponent(req.params.serverAddress || '');
		const command = req.params.command;

		if (!command || !['start', 'stop'].includes(command)) {
			return res.status(400).send('Invalid command');
		}

		const isKnownServer = [...cirrusServers.values()].some((s) => s.address === serverAddress);
		if (!isKnownServer) {
			return res.status(404).json({ error: `Unknown server address: ${serverAddress}` });
		}

		console.log(`Sending command ${command} to ${serverAddress}`);
		const result = await requestGameManager(serverAddress, `/${command}`, 'POST');
		const statusCode = result.status === 'success' ? 200 : 502;
		return res.status(statusCode).json(result);
	});

	app.get('/api/game/version', cors(), async (req, res) => {
		console.log('Broadcasting version check...');
		const results = await broadcastToGames('/version', 'GET');
		res.json({ results: results });
	});

	app.get('/api/game/stats', cors(), async (req, res) => {
		console.log('Broadcasting stats request...');
		const results = await broadcastToGames('/stats', 'GET');
		res.json({ results: results });
	});

	app.get('/api/game/stats/timeline', cors(), async (req, res) => {
		console.log('Broadcasting timeline stats request...');
		const results = await broadcastToGames('/stats/timeline', 'GET');
		res.json({ results: results });
	});
}

if (enableRedirectionLinks) {
	// Handle standard URL.
	app.get('/', (req, res) => {
		cirrusServer = getAvailableCirrusServer();
		if (cirrusServer != undefined) {
			let prefix = cirrusServer.https ? 'https://' : 'http://';
			res.redirect(`${prefix}${cirrusServer.address}:${cirrusServer.port}/`);
			console.log(`Redirect to ${cirrusServer.address}:${cirrusServer.port}`);
		} else {
			sendRetryResponse(res);
		}
	});

	// Handle URL with custom HTML.
	app.get('/custom_html/:htmlFilename', (req, res) => {
		cirrusServer = getAvailableCirrusServer();
		if (cirrusServer != undefined) {
			let prefix = cirrusServer.https ? 'https://' : 'http://';
			res.redirect(`${prefix}${cirrusServer.address}:${cirrusServer.port}/custom_html/${req.params.htmlFilename}`);
			console.log(`Redirect to ${cirrusServer.address}:${cirrusServer.port}`);
		} else {
			sendRetryResponse(res);
		}
	});
}

//
// Connection to Cirrus.
//

const net = require('net');

function disconnect(connection) {
	console.log(`Ending connection to remote address ${connection.remoteAddress}`);
	connection.end();
}

const matchmaker = net.createServer((connection) => {
	connection.on('data', (data) => {
		try {
			message = JSON.parse(data);

			if (message)
				console.log(`Message TYPE: ${message.type}`);
		} catch (e) {
			console.log(`ERROR (${e.toString()}): Failed to parse Cirrus information from data: ${data.toString()}`);
			disconnect(connection);
			return;
		}
		if (message.type === 'connect') {
			// A Cirrus server connects to this Matchmaker server.
			cirrusServer = {
				address: message.address,
				port: message.port,
				https: message.https,
				numConnectedClients: 0,
				lastPingReceived: Date.now()
			};
			cirrusServer.ready = message.ready === true;

			// Handles disconnects between MM and SS to not add dupes with numConnectedClients = 0 and redirect users to same SS
			// Check if player is connected and doing a reconnect. message.playerConnected is a new variable sent from the SS to
			// help track whether or not a player is already connected when a 'connect' message is sent (i.e., reconnect).
			if (message.playerConnected == true) {
				cirrusServer.numConnectedClients = 1;
			}

			// Find if we already have a ciruss server address connected to (possibly a reconnect happening)
			let server = [...cirrusServers.entries()].find(([key, val]) => val.address === cirrusServer.address && val.port === cirrusServer.port);

			// if a duplicate server with the same address isn't found -- add it to the map as an available server to send users to.
			if (!server || server.size <= 0) {
				console.log(`Adding connection for ${cirrusServer.address.split(".")[0]} with playerConnected: ${message.playerConnected}`)
				cirrusServers.set(connection, cirrusServer);
			} else {
				console.log(`RECONNECT: cirrus server address ${cirrusServer.address.split(".")[0]} already found--replacing. playerConnected: ${message.playerConnected}`)
				var foundServer = cirrusServers.get(server[0]);

				// Make sure to retain the numConnectedClients from the last one before the reconnect to MM
				if (foundServer) {
					cirrusServers.set(connection, cirrusServer);
					console.log(`Replacing server with original with numConn: ${cirrusServer.numConnectedClients}`);
					cirrusServers.delete(server[0]);
				} else {
					cirrusServers.set(connection, cirrusServer);
					console.log("Connection not found in Map() -- adding a new one");
				}
			}
		} else if (message.type === 'streamerConnected') {
			// The stream connects to a Cirrus server and so is ready to be used
			cirrusServer = cirrusServers.get(connection);
			if (cirrusServer) {
				cirrusServer.ready = true;
				console.log(`Cirrus server ${cirrusServer.address}:${cirrusServer.port} ready for use`);
			} else {
				disconnect(connection);
			}
		} else if (message.type === 'streamerDisconnected') {
			// The stream connects to a Cirrus server and so is ready to be used
			cirrusServer = cirrusServers.get(connection);
			if (cirrusServer) {
				cirrusServer.ready = false;
				console.log(`Cirrus server ${cirrusServer.address}:${cirrusServer.port} no longer ready for use`);
			} else {
				disconnect(connection);
			}
		} else if (message.type === 'clientConnected') {
			// A client connects to a Cirrus server.
			cirrusServer = cirrusServers.get(connection);
			if (cirrusServer) {
				cirrusServer.numConnectedClients++;
				console.log(`Client connected to Cirrus server ${cirrusServer.address}:${cirrusServer.port}`);
			} else {
				disconnect(connection);
			}
		} else if (message.type === 'clientDisconnected') {
			// A client disconnects from a Cirrus server.
			cirrusServer = cirrusServers.get(connection);
			if (cirrusServer) {
				cirrusServer.numConnectedClients--;
				console.log(`Client disconnected from Cirrus server ${cirrusServer.address}:${cirrusServer.port}`);
				if (cirrusServer.numConnectedClients === 0) {
					// this make this server immediately available for a new client
					cirrusServer.lastRedirect = 0;
				}
			} else {
				disconnect(connection);
			}
		} else if (message.type === 'ping') {
			cirrusServer = cirrusServers.get(connection);
			if (cirrusServer) {
				cirrusServer.lastPingReceived = Date.now();
			} else {
				disconnect(connection);
			}
		} else {
			console.log('ERROR: Unknown data: ' + JSON.stringify(message));
			disconnect(connection);
		}
	});

	// A Cirrus server disconnects from this Matchmaker server.
	connection.on('error', () => {
		cirrusServer = cirrusServers.get(connection);
		if (cirrusServer) {
			cirrusServers.delete(connection);
			console.log(`Cirrus server ${cirrusServer.address}:${cirrusServer.port} disconnected from Matchmaker`);
		} else {
			console.log(`Disconnected machine that wasn't a registered cirrus server, remote address: ${connection.remoteAddress}`);
		}
	});
});

matchmaker.listen(config.MatchmakerPort, () => {
	console.log('Matchmaker listening on *:' + config.MatchmakerPort);
});
