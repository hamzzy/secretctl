import * as net from "net";

export class LengthPrefixedSocket {
  private socket: net.Socket;
  private buffer: Buffer = Buffer.alloc(0);
  private messageQueue: ((msg: Buffer) => void)[] = [];

  constructor(socket: net.Socket) {
    this.socket = socket;
    this.socket.on("data", (chunk: Buffer) => this.onData(chunk));
  }

  private onData(chunk: Buffer) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (this.buffer.length < 4 + length) {
        break;
      }
      const message = this.buffer.subarray(4, 4 + length);
      this.buffer = this.buffer.subarray(4 + length);

      if (this.messageQueue.length > 0) {
        const resolver = this.messageQueue.shift()!;
        resolver(message);
      }
    }
  }

  public send(payload: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);
      const frame = Buffer.concat([header, payload]);
      this.socket.write(frame, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  public readNext(): Promise<Buffer> {
    return new Promise((resolve) => {
      this.messageQueue.push(resolve);
    });
  }

  public close() {
    this.socket.end();
  }
}
