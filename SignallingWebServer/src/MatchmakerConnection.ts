import * as net from 'net';
import { SignallingServer } from '@epicgames-ps/lib-pixelstreamingsignalling-ue5.5';
import { Logger } from '@epicgames-ps/lib-pixelstreamingsignalling-ue5.5';

/**
 * Handles the connection to the Matchmaker server.
 * Connects via TCP and communicates streamer/player state.
 */
export class MatchmakerConnection {
    private matchmakerAddress: string;
    private matchmakerPort: number;
    private retryInterval: number;
    private socket: net.Socket;
    private signallingServer: SignallingServer;
    private playerPort: number;
    private httpsPort: number;
    private useHttps: boolean;
    private publicIp: string;

    constructor(
        signallingServer: SignallingServer,
        matchmakerAddress: string,
        matchmakerPort: number,
        retryInterval: number,
        playerPort: number,
        httpsPort: number,
        useHttps: boolean,
        publicIp: string
    ) {
        this.signallingServer = signallingServer;
        this.matchmakerAddress = matchmakerAddress;
        this.matchmakerPort = matchmakerPort;
        this.retryInterval = retryInterval;
        this.playerPort = playerPort;
        this.httpsPort = httpsPort;
        this.useHttps = useHttps;
        this.publicIp = publicIp;
        this.socket = new net.Socket();

        this.setupMatchmakerEvents();
        this.setupSignallingEvents();
        this.connect();
    }

    private connect(): void {
        Logger.info(`Connecting to Matchmaker at ${this.matchmakerAddress}:${this.matchmakerPort}...`);
        this.socket.connect(this.matchmakerPort, this.matchmakerAddress);
    }

    private reconnect(): void {
        Logger.info(`Reconnecting to Matchmaker in ${this.retryInterval} seconds...`);
        setTimeout(() => {
            this.connect();
        }, this.retryInterval * 1000);
    }

    private setupMatchmakerEvents(): void {
        this.socket.on('connect', () => {
            Logger.info(`Connected to Matchmaker ${this.matchmakerAddress}:${this.matchmakerPort}`);

            // Send 'connect' message
            const message = {
                type: 'connect',
                address: this.publicIp,
                https: this.useHttps,
                port: this.useHttps ? this.httpsPort : this.playerPort,
                ready: !this.signallingServer.streamerRegistry.empty(),
                playerConnected: !this.signallingServer.playerRegistry.empty()
            };
            this.socket.write(JSON.stringify(message));
        });

        this.socket.on('error', (err) => {
            Logger.error(`Matchmaker connection error: ${err.message}`);
        });

        this.socket.on('close', (hadError) => {
            Logger.info(`Matchmaker connection closed (hadError=${hadError})`);
            this.reconnect();
        });

        // Keep Alive
        setInterval(() => {
            if (this.socket.readyState === 'open') {
                this.socket.write(JSON.stringify({ type: 'ping' }));
            }
        }, 30000);
    }

    private setupSignallingEvents(): void {
        // Streamer Added
        this.signallingServer.streamerRegistry.on('added', (streamerId: string) => {
            Logger.info(`MatchmakerConnection: Streamer added ${streamerId}`);
            if (this.socket.readyState === 'open') {
                this.socket.write(JSON.stringify({ type: 'streamerConnected' }));
            }
        });

        // Streamer Removed
        this.signallingServer.streamerRegistry.on('removed', (streamerId: string) => {
            Logger.info(`MatchmakerConnection: Streamer removed ${streamerId}`);
            if (this.socket.readyState === 'open') {
                this.socket.write(JSON.stringify({ type: 'streamerDisconnected' }));
            }
        });

        // Player Added
        this.signallingServer.playerRegistry.on('added', (playerId: string) => {
            Logger.info(`MatchmakerConnection: Player added ${playerId}`);
            if (this.socket.readyState === 'open') {
                this.socket.write(JSON.stringify({ type: 'clientConnected' }));
            }
        });

        // Player Removed
        this.signallingServer.playerRegistry.on('removed', (playerId: string) => {
            Logger.info(`MatchmakerConnection: Player removed ${playerId}`);
            if (this.socket.readyState === 'open') {
                this.socket.write(JSON.stringify({ type: 'clientDisconnected' }));
            }
        });
    }
}
