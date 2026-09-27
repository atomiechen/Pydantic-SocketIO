// Generated from a Pydantic-SocketIO AsyncAPI contract. Do not edit.
// Client: Socket<ServerToClientEvents, ClientToServerEvents>.
// Server: Server<ClientToServerEvents, ServerToClientEvents> for /; Namespace<...> for other paths.
export interface Answer {
  accepted: boolean;
}
export interface Ask {
  text: string;
}
export interface Notice {
  text: string;
}
export namespace Chat {
  export const path = "/chat";
  export interface ClientToServerEvents {
    "ask": (...args: [...[request: Ask], ack?: (...args: [Answer]) => void]) => void;
  }
  export interface ServerToClientEvents {
    "notice": (...args: [...[Notice], ack?: (...args: unknown[]) => void]) => void;
  }
}
