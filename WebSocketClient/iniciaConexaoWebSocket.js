const socket = new WebSocket("wss://localhost:51957");

socket.addEventListener("open", (event) => {
    console.log("Conexão aberta com sucesso.");

    // Realize o handshake WebSocket
    const handshake = createWebSocketHandshake();
    socket.send(handshake);
});

socket.addEventListener("message", (event) => {
    console.log("Mensagem recebida do servidor:", event.data);

    // Aqui você pode processar as mensagens recebidas do servidor.
    // Lembre-se de que o servidor pode enviar mensagens após o handshake.
});

socket.addEventListener("close", (event) => {
    console.log("Conexão fechada.");
});

socket.addEventListener("error", (event) => {
    console.error("Erro na conexão:", event);
});

// Função para criar um handshake WebSocket
function createWebSocketHandshake() {
    const key = generateWebSocketKey();
    return `GET / HTTP/1.1\r\n` +
        `Host: localhost:51957\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`;
}

// Função para gerar uma chave WebSocket
function generateWebSocketKey() {
    const key = new Array(16);
    for (let i = 0; i < key.length; i++) {
        key[i] = String.fromCharCode(Math.floor(Math.random() * 256));
    }
    return btoa(key.join(''));
}
