# Carrega a biblioteca de Windows Forms
Add-Type -AssemblyName System.Net.Http

# URL do servidor WebSocket
$websocketUrl = "ws://localhost/seusocket"

# Cria uma instância de ClientWebSocket
$websocket = [System.Net.WebSockets.ClientWebSocket]::new()

# Conecta ao servidor WebSocket
$websocket.ConnectAsync([System.Uri] $websocketUrl, [System.Threading.CancellationToken]::None).Wait()

# Cria um buffer para receber dados do servidor WebSocket
$buffer = [System.Array]::CreateInstance([byte], 1024)

# Loop para receber e processar mensagens WebSocket
while ($true) {
    $result = $websocket.ReceiveAsync($buffer, [System.Threading.CancellationToken]::None).Result
    $message = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
    Write-Host "Mensagem recebida: $message"
}

# Fechar a conexão quando necessário
$websocket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Fechando conexão", [System.Threading.CancellationToken]::None).Wait()
