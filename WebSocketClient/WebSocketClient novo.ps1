# URL do servidor WebSocket (substitua pelo endereço do seu servidor)
$serverUrl = "ws://localhost:8080"

# Crie um cliente WebSocket
$socket = New-Object System.Net.WebSockets.ClientWebSocket

# Conecte-se ao servidor WebSocket
$socket.ConnectAsync([System.Uri]$serverUrl, $null).GetAwaiter().GetResult()

# Loop para enviar e receber mensagens
while ($true) {
    # Leia a entrada do usuário
    $message = Read-Host "Digite uma mensagem (ou 'exit' para sair)"

    if ($message -eq "exit") {
        break
    }

    # Converte a mensagem em bytes
    $messageBytes = [System.Text.Encoding]::UTF8.GetBytes($message)

    # Crie um quadro WebSocket com a mensagem
    $messageFrame = [System.Net.WebSockets.WebSocketMessageType]::Text
    $messageBuffer = [System.Net.WebSockets.WebSocketMessage]::CreateClientBuffer($messageBytes, $messageFrame, $true)

    # Envie a mensagem para o servidor
    $socket.SendAsync($messageBuffer, $messageFrame, $true, $null).GetAwaiter().GetResult()

    # Aguarde a resposta do servidor
    $responseBuffer = New-Object byte[] 1024
    $response = $null

    $receiveResult = $null
    do {
        $receiveResult = $socket.ReceiveAsync($responseBuffer, $null).GetAwaiter().GetResult()
        $response += [System.Text.Encoding]::UTF8.GetString($responseBuffer, 0, $receiveResult.Count)
    } while (!$receiveResult.EndOfMessage)

    Write-Host "Resposta do servidor: $response"
}

# Feche a conexão
$socket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Fechando conexão", $null).GetAwaiter().GetResult()
