# $websocketUrl = "wss://localhost:51957"

# Carrega a biblioteca de Windows Forms
Add-Type -AssemblyName System.Net.Http

# URL do servidor WebSocket
$websocketUrl = "wss://localhost:51957"

# Cria uma instância de ClientWebSocket
$websocket = [System.Net.WebSockets.ClientWebSocket]::new()

# Conecta ao servidor WebSocket
$websocket.ConnectAsync([System.Uri] $websocketUrl, [System.Threading.CancellationToken]::None).Wait()

# Mensagem a ser enviada em UTF-8
$message = "GET"
$buffer = [System.Text.Encoding]::UTF8.GetBytes($message)

# Envia a mensagem para o servidor WebSocket
try {
    $websocket.SendAsync($buffer, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None).Wait()
    Write-Host "Mensagem enviada: $message"
} catch {
    Write-Host "Erro ao enviar mensagem: $_"
    if ($_.InnerException) {
        Write-Host "Erro interno: $($_.InnerException.Message)"
    }
    break  # Sair do loop se ocorrer um erro
}

<#
# Cria um buffer para receber dados do servidor WebSocket
$buffer = [System.Array]::CreateInstance([byte], 1024)

$result = $websocket.ReceiveAsync($buffer, [System.Threading.CancellationToken]::None).Result
$receivedMessage = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
Write-Host "Mensagem recebida: $receivedMessage"
#>

# Fechar a conexão quando necessário
$websocket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Fechando conexão", [System.Threading.CancellationToken]::None).Wait()
