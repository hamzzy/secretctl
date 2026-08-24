import * as net from "net";

export class LengthPrefixedSocket {
  private socket: net.Socket;
  private buffer: Buffer = Buffer.alloc(0);
  private messageQueue: Array<{ resolve: (msg: Buffer) => void; reject: (error: Error) => void }> = [];
  private bufferedMessages: Buffer[] = [];
  private closedError?: Error;

  constructor(socket: net.Socket) {
    this.socket = socket;
    this.socket.on("data", (chunk: Buffer) => this.onData(chunk));
    this.socket.on("error", (error) => this.fail(error));
    this.socket.on("close", () => this.fail(new Error("secretctl transport closed")));
  }

  private fail(error: Error) {
    if (this.closedError) return;
    this.closedError = error;
    for (const waiter of this.messageQueue.splice(0)) waiter.reject(error);
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
        const waiter = this.messageQueue.shift()!;
        waiter.resolve(message);
      } else {
        this.bufferedMessages.push(Buffer.from(message));
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
    const buffered = this.bufferedMessages.shift();
    if (buffered) return Promise.resolve(buffered);
    if (this.closedError) return Promise.reject(this.closedError);
    return new Promise((resolve, reject) => {
      this.messageQueue.push({ resolve, reject });
    });
  }

  public close() {
    this.socket.end();
  }
}
