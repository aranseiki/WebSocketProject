# Função para autenticar o cliente e receber o token de autenticação
function AuthenticateClient($clientStream) {
    try {
        # Receba o token de autenticação do cliente
        $token = ReceiveAuthenticationToken $clientStream

        # Valide o token (verifique se ele é válido no seu sistema)
        if (IsValidToken $token) {
            LogEvent "Info" "Cliente autenticado com sucesso"
            Write-Host "Info" "Cliente autenticado com sucesso"
            return $token
        } else {
            LogEvent "Erro" "Falha na autenticação do cliente"
            Write-Host "Erro" "Falha na autenticação do cliente"
            return $null
        }
    } catch {
        LogEvent "Erro" "Erro durante a autenticação do cliente: $($_)"
        Write-Host "Erro" "Erro durante a autenticação do cliente: $($_)"
        return $null
    }
}

# Função para escolher o endereço IP de escuta com tratamento de exceções
function ChooseListeningIP([System.Net.IPAddress] $ipUser = $null) {
    try {
        $ipAddress = [System.Net.IPAddress]::Any
        if ($null -ne $ipUser) {
            $ipAddress = [System.Net.IPAddress]::Parse($ipUser)
        }
        return $ipAddress
    } catch {
        LogEvent "Erro" "Erro ao escolher o endereço IP de escuta: $($_)"
        Write-Host "Erro" "Erro ao escolher o endereço IP de escuta: $($_)"
        return $null
    }
}

# Função para escolher a porta de escuta com tratamento de exceções
function ChooseListeningPort([int] $portUser = $null) {
    try {
        $port = 8080
        if ($null -ne $portUser) {
            $port = $portUser
        }
        return $port
    } catch {
        LogEvent "Erro" "Erro ao escolher a porta de escuta: $($_)"
        Write-Host "Erro" "Erro ao escolher a porta de escuta: $($_)"
        return $null
    }
}

# Função para decodificar um quadro WebSocket em um chunk de arquivo
function DecodeFileChunk($frame) {
    try {
        $length = $frame[1] -band 0x7F  # Obtém o tamanho do chunk
        $payload = $frame[2..($length + 1)]  # Obtém a carga útil (chunk)

        return $payload
    } catch {
        # Tratar exceções aqui
        LogEvent "Erro" "Erro ao decodificar chunk de arquivo: $($_)"
        Write-Host "Erro" "Erro ao decodificar chunk de arquivo: $($_)"
        return @()  # Retorna um array vazio em caso de erro
    }
}

# Função para decodificar um quadro WebSocket da requisição do cliente
function DecodeWebSocketClientFrame([string] $frameData) {
    $length = $frameData[1] -band 0x7F
    $payloadData = $frameData.Substring(2, $length)

    return $payloadData
}

# Função para decodificar um quadro WebSocket em uma mensagem de texto
function DecodeWebSocketFrame($frame) {
    try {
        $opcode = $frame[0] -band 0xF  # Obtém o código de operação
        $length = $frame[1] -band 0x7F  # Obtém o tamanho da carga útil

        $payload = $frame[2..($length + 1)]  # Obtém a carga útil
        $decodedMessage = [System.Text.Encoding]::UTF8.GetString($payload)

        return $decodedMessage
    } catch {
        # Tratar exceções aqui
        LogEvent "Erro" "Erro ao decodificar chunk de arquivo: $($_)"
        Write-Host "Erro" "Erro ao decodificar chunk de arquivo: $($_)"
        return @()  # Retorna um array vazio em caso de erro
    }
}

# Função para codificar um chunk de arquivo em um quadro WebSocket
function EncodeFileChunk($chunk) {
    try {
        $length = $chunk.Length
        $header = [byte[]]@(0x82)  # Indica um quadro de dados binários (opcode 0x2)

        if ($length -le 125) {
            $header += [byte]$length
        } elseif ($length -le 65535) {
            $header += [byte]126
            $header += [byte[]]@($length -shr 8, $length -band 255)
        } else {
            $header += [byte]127
            $header += [byte[]]@(
                $length -shr 56,
                $length -shr 48,
                $length -shr 40,
                $length -shr 32,
                $length -shr 24,
                $length -shr 16,
                $length -shr 8,
                $length -band 255
            )
        }

        $encodedChunk = $header + [byte[]]$chunk
        return $encodedChunk
    } catch {
        # Tratar exceções aqui, se necessário
        LogEvent "Erro" "Erro ao codificar chunk de arquivo: $($_)"
        Write-Host "Erro" "Erro ao codificar chunk de arquivo: $($_)"
        return @()  # Retorna um array vazio em caso de erro
    }
}

# Função para verificar se o usuário está autorizado com base no token JWT e na chave secreta
function IsAuthorized($token) {
    try {
        # Importar a biblioteca JWT
        Add-Type -Path "System.IdentityModel.Tokens.Jwt.dll"

        # Decodificar o token JWT e obter as reivindicações (claims)
        $tokenHandler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
        $tokenValidationParameters = @{
            "ValidIssuer" = "sua-emissora.com"  # Substitua pelo emissor válido
            "ValidAudience" = "seu-aplicativo.com"  # Substitua pela audiência válida
            "IssuerSigningKey" = [System.Text.Encoding]::UTF8.GetBytes($secretKey)  # Use a chave secreta
        }

        $claimsPrincipal = $tokenHandler.ValidateToken($token, $tokenValidationParameters, [ref]$null)
        $claimsIdentity = $claimsPrincipal.Identity

        # Verificar a autorização com base nas reivindicações (claims)
        # Por exemplo, você pode verificar se o usuário tem acesso ao recurso solicitado
        if ($claimsIdentity.HasClaim("role", "admin")) {
            return $true
        }

        # Se o usuário não estiver autorizado, retorne $false
        return $false
    } catch {
        # Tratar exceções aqui, se ocorrerem erros durante a verificação da autorização
        return $false
    }
}

# Função para validar se um token JWT é válido
function IsValidToken($token) {
    try {
        # Importar a biblioteca JWT
        Add-Type -Path "System.IdentityModel.Tokens.Jwt.dll"

        # Decodificar o token JWT
        $tokenHandler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
        $tokenValidationParameters = @{
            "IssuerSigningKey" = [System.Text.Encoding]::UTF8.GetBytes($secretKey)  # Use a chave secreta
            "ValidIssuer" = "sua-emissora.com"  # Substitua pelo emissor válido
            "ValidAudience" = "seu-aplicativo.com"  # Substitua pela audiência válida
        }

        $tokenHandler.ValidateToken($token, $tokenValidationParameters, [ref]$null)

        # Se a validação for bem-sucedida, o token é válido
        return $true
    } catch {
        # Tratar exceções aqui, se ocorrerem erros durante a validação do token
        return $false
    }
}

# Função para verificar se a origem é permitida com tratamento de exceções
function IsOriginAllowed($origin) {
    try {
        $allowedOrigins = @("https://example.com", "https://anotherdomain.com")
        return $allowedOrigins -contains $origin
    } catch {
        LogEvent "Erro" "Erro ao verificar a origem permitida: $($_)"
        Write-Host "Erro" "Erro ao verificar a origem permitida: $($_)"
        return $false
    }
}

# Função para registrar eventos em um arquivo de log
function LogEvent($eventType, $message) {
    try {
        $logFilePath = "C:\dev\WebSocketServer\log.txt"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp - [$eventType] - $message"

        # Adicione código para escrever $logMessage no arquivo de log
        Add-Content -Path $logFilePath -Value $logMessage
    } catch {
        # Tratar exceções aqui
        Write-Host "Erro ao registrar evento no log: $($_)"
    }
}

# Função para processar mensagens WebSocket (lida com a transferência de arquivos)
function ProcessWebSocketMessage($message, $clientStream, $jwtToken, $secretKey) {
    try {
        # Converta o array de bytes em uma string para facilitar o processamento
        $messageString = [System.Text.Encoding]::UTF8.GetString($message)

        # Verifique se o cliente solicitou uma transferência de arquivo
        if ($messageString -match "^TRANSFER_FILE:(.*)$") {
            # Verifique a autorização para acessar o recurso
            if (IsAuthorized $jwtToken $secretKey) {
                # Executar lógica de transferência de arquivo aqui
            } else {
                LogEvent "Erro" "Acesso não autorizado ao recurso de arquivo"
                Write-Host "Erro" "Acesso não autorizado ao recurso de arquivo"
                # Envie uma mensagem de erro ao cliente, se necessário
            }
        }
        # Verifique se o cliente solicitou a transferência de uma pasta
        elseif ($messageString -match "^TRANSFER_FOLDER:(.*)$") {
            # Extrair o nome da pasta da mensagem
            $folderName = $matches[1]

            # Mapear o nome da pasta para o caminho físico no servidor (exemplo)
            $folderPathMap = @{
                "Pasta1" = "C:\dev\projects\Pasta1"
                "Pasta2" = "C:\dev\projects\Pasta2"
                # Adicione mais mapeamentos conforme necessário
            }

            # 
            LogEvent "Info" "Verificando se a pasta está mapeada"
            Write-Host "Info" "Verificando se a pasta está mapeada"
            if ($folderPathMap.ContainsKey($folderName)) {
                $folderPath = $folderPathMap[$folderName]

                # Verifique a autorização para acessar o recurso
                if (IsAuthorized $jwtToken $secretKey) {
                    # Inicie a transferência da pasta escolhida
                    LogEvent "Info" "Iniciando transferência da pasta: $folderName"
                    Write-Host "Info" "Iniciando transferência da pasta: $folderName"
                    StartFolderTransfer $folderPath $clientStream
                } else {
                    Write-Host "Erro" "Acesso não autorizado ao recurso de pasta"
                    LogEvent "Erro" "Acesso não autorizado ao recurso de pasta"
                }
            } else {
                LogEvent "Erro" "Pasta não encontrada: $folderName"
                Write-Host "Erro" "Pasta não encontrada: $folderName"
            }
        } else {
            LogEvent "Info" "Mensagem recebida: $messageString"
            Write-Host "Info" "Mensagem recebida: $messageString"
        }
    } catch {
        LogEvent "Erro" "Erro durante o processamento da mensagem: $($_)"
        Write-Host "Erro" "Erro durante o processamento da mensagem: $($_)"
    }
}

# Função para receber e decodificar o token de autenticação do cliente com tratamento de exceções
function ReceiveAuthenticationToken($clientStream) {
    try {
        $bufferSize = 1024
        $token = ""
    
        LogEvent "Info" "Aguardando a chegada de dados do cliente"
        Write-Host "Info" "Aguardando a chegada de dados do cliente"
        $data = New-Object byte[] $bufferSize
        $bytesRead = $clientStream.Read($data, 0, $data.Length)
    
        if ($bytesRead -le 0) {
            LogEvent "Info" "A conexão foi fechada pelo cliente ou houve um erro"
            Write-Host "Info" "A conexão foi fechada pelo cliente ou houve um erro"
            return $token
        }
        
        LogEvent "Info" "Decodificando a mensagem WebSocket recebida"
        Write-Host "Info" "Decodificando a mensagem WebSocket recebida"
        $decodedData = DecodeFileChunk $data
    
        LogEvent "Info" "Combinando os dados decodificados e formando o token completo"
        Write-Host "Info" "Combinando os dados decodificados e formando o token completo"
        $token += $decodedData
    
        return $token
    } catch {
        LogEvent "Erro" "Erro durante o recebimento e decodificação do token: $($_)"
        Write-Host "Erro" "Erro durante o recebimento e decodificação do token: $($_)"
        return $null
    }
}

# Função para receber mensagens WebSocket
function ReceiveWebSocketMessage($stream) {
    try {
        $header = [byte[]]::new(2)
        $stream.Read($header, 0, 2)

        $opcode = $header[0] -band 0x0F
        $payloadLen = $header[1] -band 0x7F

        if ($payloadLen -eq 126) {
            $lenBytes = [byte[]]::new(2)
            $stream.Read($lenBytes, 0, 2)
            $payloadLen = [BitConverter]::ToUInt16($lenBytes, 0)
        } elseif ($payloadLen -eq 127) {
            $lenBytes = [byte[]]::new(8)
            $stream.Read($lenBytes, 0, 8)
            $payloadLen = [BitConverter]::ToUInt64($lenBytes, 0)
        }

        $maskingKey = [byte[]]::new(4)
        $stream.Read($maskingKey, 0, 4)

        $payload = [byte[]]::new($payloadLen)
        $stream.Read($payload, 0, $payloadLen)

        for ($i = 0; $i -lt $payloadLen; $i++) {
            $payload[$i] = [byte]($payload[$i] -bxor $maskingKey[$i % 4])
        }

        $message = [System.Text.Encoding]::UTF8.GetString($payload)
        return $message
    } catch {
        # Tratamento de erro ao ler da conexão
        Write-Host "Erro ao ler da conexão: $($_.Exception.Message)"
        return $null  # Retorna null para indicar erro
    }
}

# Função para iniciar a transferência de um arquivo do lado do servidor
function StartFileTransfer($filePath, $clientStream) {
    try {
        # Abra o arquivo para leitura
        $fileStream = [System.IO.File]::OpenRead($filePath)
        $buffer = New-Object byte[] 1024
        $bytesRead = 0

        while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            # Codificar o chunk do arquivo e enviar ao cliente
            $encodedChunk = EncodeFileChunk $buffer[0..($bytesRead - 1)]
            $clientStream.Write($encodedChunk, 0, $encodedChunk.Length)
            $clientStream.Flush()
        }
        LogEvent "Sucesso" "Transferência do arquivo concluída: $($filePath)"
        Write-Host "Sucesso" "Transferência do arquivo concluída: $($filePath)"
    } catch {
        LogEvent "Erro" "Erro durante a transferência do arquivo: $($filePath) - $($_)"
        Write-Host "Erro" "Erro durante a transferência do arquivo: $($filePath) - $($_)"
    } finally {
        if ($null -ne $fileStream) {
            $fileStream.Close()
            LogEvent "Sucesso" "Transferência do arquivo concluída: $($filePath)"
            Write-Host "Sucesso" "Transferência do arquivo concluída: $($filePath)"
        }
    }
}

# Função para iniciar a transferência de uma pasta com subpastas e arquivos do lado do servidor
function StartFolderTransfer($folderPath, $clientStream) {
    try {
        # Lista todos os arquivos na pasta
        $files = Get-ChildItem $folderPath | Where-Object { $_.PSIsContainer -eq $false }

        # Para cada arquivo na pasta, envie-o para o cliente
        foreach ($file in $files) {
            $filePath = $file.FullName
            LogEvent "Info" "Enviando arquivo: $filePath"
            Write-Host "Info" "Enviando arquivo: $filePath"

            # Abra o arquivo para leitura
            $fileStream = [System.IO.File]::OpenRead($filePath)
            $buffer = New-Object byte[] 1024
            $bytesRead = 0

            while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                # Codificar o chunk do arquivo e enviar ao cliente
                $encodedChunk = EncodeFileChunk $buffer[0..($bytesRead - 1)]
                $clientStream.Write($encodedChunk, 0, $encodedChunk.Length)
                $clientStream.Flush()
            }

            # Aguardar um curto intervalo entre os arquivos (opcional)
            Start-Sleep -Milliseconds 100
        }

        LogEvent "Sucesso" "Transferência da pasta concluída: $($folderPath)"
        Write-Host "Sucesso" "Transferência da pasta concluída: $($folderPath)"
    } catch {
        LogEvent "Erro" "Erro durante a transferência da pasta: $($folderPath) - $($_)"
        Write-Host "Erro" "Erro durante a transferência da pasta: $($folderPath) - $($_)"
    } finally {
        if ($null -ne $fileStream) {
            $fileStream.Close()
            LogEvent "Sucesso" "Transferência do arquivo concluída: $($filePath)"
            Write-Host "Sucesso" "Transferência do arquivo concluída: $($filePath)"
        }
    }
}

# Função para iniciar aguardar conexão com o servidor WebSocket
function StartWebSocketListener {
    param (
        [int] $port,
        [System.Net.IPAddress] $ipAddress,
        [bool] $secure,
        [string] $secretKey,
        [string] $certificateThumbprint
    )

    try{
        LogEvent "Info" "Criando um socket do Servidor"
        Write-Host "Info" "Criando um socket do Servidor"
        $listener = [System.Net.Sockets.TcpListener]::new($ipAddress, $port)

        LogEvent "Info" "Iniciando o socket do servidor"
        Write-Host "Info" "Iniciando o socket do servidor"
        $listener.Start()

        LogEvent "Info" "Aguardando por Conexões"
        Write-Host "Info" "Aguardando por Conexões"
        if ($secure) {
            LogEvent "Info" "Autenticando por SSL"
            Write-Host "Info" "Autenticando por SSL"
            LogEvent "Info" "Servidor conectado em: $($listener.Server.LocalEndPoint.ToString())"
            Write-Host "Info" "Servidor conectado em: $($listener.Server.LocalEndPoint.ToString())"

            # Configurar a segurança com base no certificado
            $cert = Get-Item -Path cert:\LocalMachine\My\$certificateThumbprint -ErrorAction Stop
            $tcpClient = $listener.AcceptTcpClient()
            $networkStream = $tcpClient.GetStream()
            $sslStream = [System.Net.Security.SslStream]::new($networkStream, $false)
            $sslStream.AuthenticateAsServer($cert, $false, $sslProtocols, $false)
            $sslProtocols = [System.Security.Authentication.SslProtocols]::Tls

            $clientStream = $sslStream
        } else {
            LogEvent "Info" "Autenticando sem SSL"
            Write-Host "Info" "Autenticando sem SSL"
            $tcpClient = $listener.AcceptTcpClient()
            $networkStream = $tcpClient.GetStream()
            $clientStream = $networkStream
        }

        LogEvent "Info" "Lendo a requisição do cliente"
        Write-Host "Info" "Lendo a requisição do cliente"
        # $reader = [System.IO.StreamReader]::new($clientStream, [System.Text.Encoding]::UTF8)

        # $buffer = New-Object byte[] 4096
        # $read = $reader.Read($buffer, 0, $buffer.Length)
        # $message = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        
        $message = ReceiveWebSocketMessage $clientStream
        Write-Host $message
        Wait-Debugger

        if (([string]::IsNullOrWhiteSpace($reader)) -eq $false) {
            $request = $reader.ReadLine()
        } else {
            LogEvent "Erro" "A requisição está vazia. Envie alguma mensagem na requisição pelo cliente"
            Write-Error "Erro" "A requisição está vazia. Envie alguma mensagem na requisição pelo cliente"

            continue
        }

        LogEvent "Info" "Verificando se a requisição é um handshake WebSocket"
        Write-Host "Info" "Verificando se a requisição é um handshake WebSocket"
        # Wait-Debugger
        # $request = DecodeWebSocketClientFrame -frame $request
        if ($request -match "Sec-WebSocket-Key:") {
            LogEvent "Info" "Recuperando a chave do cabeçalho do cliente"
            Write-Host "Info" "Recuperando a chave do cabeçalho do cliente"
            $clientKey = $request -replace ".*Sec-WebSocket-Key: (.+).*", '$1'
        
            LogEvent "Info" "Calculando a chave de resposta (WebSocket protocol magic string + clientKey + SHA-1 hash)"
            Write-Host "Info" "Calculando a chave de resposta (WebSocket protocol magic string + clientKey + SHA-1 hash)"
            $magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            $combinedKey = $clientKey + $magicString
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            $hashedBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedKey))
            $responseKey = [Convert]::ToBase64String($hashedBytes)

            LogEvent "Info" "Montando a resposta do servidor"
            Write-Host "Info" "Montando a resposta do servidor"
            $response = "HTTP/1.1 101 Switching Protocols`r`n"
            $response += "Upgrade: websocket`r`n"
            $response += "Connection: Upgrade`r`n"
            $response += "Sec-WebSocket-Accept: $responseKey`r`n`r`n"

            LogEvent "Info" "Enviando a resposta de volta ao cliente"
            Write-Host "Info" "Enviando a resposta de volta ao cliente"
            $writer = [System.IO.StreamWriter]::new($networkStream)
            $writer.Write($response)
            $writer.Flush()

            LogEvent "Info" "Handshake WebSocket bem-sucedido"
            Write-Host "Info" "Handshake WebSocket bem-sucedido"

            while ($true) {
                param($clientStream)
                LogEvent "Info" "Cliente conectado"
                Write-Host "Info" "Cliente conectado"
        
                # Autenticar o cliente e receber o token
                $token = AuthenticateClient $clientStream
                if ($null -ne $token) {
                    # Processar mensagens do cliente
                    while ($true) {
                        $message = ReceiveAuthenticationToken $clientStream
                        if ($message.Length -eq 0) {
                            # A conexão foi fechada pelo cliente ou houve um erro
                            break
                        }
        
                        LogEvent "Info" "Processando a mensagem recebida"
                        Write-Host "Info" "Processando a mensagem recebida"
                        ProcessWebSocketMessage $message $clientStream $token
                    }
                }
            }
        } else {
            # A requisição não é um handshake WebSocket válida, você pode tratar isso adequadamente
            LogEvent "Erro" "Requisição inválida para WebSocket"
            Write-Host "Erro" "Requisição inválida para WebSocket"
        }
        
        # Fechar a conexão com o cliente
        $clientStream.Close()
        LogEvent "Info" "Conexão com o cliente fechada"
        Write-Host "Info" "Conexão com o cliente fechada"
    } catch {
        LogEvent "Erro" "Ocorreu um erro: $($_)"
        Write-Host "Erro" "Ocorreu um erro: $($_)"
    } finally {
        if ($null -ne $clientStream) {
            $clientStream.Close()
            LogEvent "Info" "Conexão com o cliente fechada"
            Write-Host "Info" "Conexão com o cliente fechada"
        }

        if ($null -ne $listener) {
            $listener.Stop()
            LogEvent "Info" "Servidor WebSocket encerrado."
            Write-Host "Info" "Servidor WebSocket encerrado."
        }
    }
}

# Função para iniciar o servidor WebSocket
function StartWebSocketServer() {
    param(
        $ipAddress,
        [int] $port,
        [bool] $Secure,
        [string] $secretKey,
        [string] $certificateThumbprint
    )

    try {
        LogEvent "Info" "Iniciando servidor WebSocket"

        # Exemplo de uso das funções
        LogEvent "Info" "Escolhendo um IP de Escuta"
        Write-Host "Info" "Escolhendo um IP de Escuta"
        $ipAddress = ChooseListeningIP -ipUser $ipAddress

        LogEvent "Info" "IP escolhido:" $ipAddress
        Write-Host "Info" "IP escolhido:" $ipAddress

        LogEvent "Info" "Escolhendo uma Porta de Escuta"
        Write-Host "Info" "Escolhendo uma Porta de Escuta"
        $port = ChooseListeningPort -portUser $port

        LogEvent "Info" "Porta escolhida:" $port
        Write-Host "Info" "Porta escolhida:" $port

        StartWebSocketListener -Port $port `
            -ipAddress $ipAddress `
            -Secure $secure `
            -CertificateThumbprint $certificateThumbprint `
            -secretKey $secretKey
    } catch {
        LogEvent "Erro" "Ocorreu um erro: $($_)"
        Write-Host "Erro" "Ocorreu um erro: $($_)"
    }
}

$ipAddress = $null
$port = 51957
$secure = $false
$secretKey = $env:WEBSOCKET_SERVER_SECRET_KEY
$certificateThumbprint = $env:WEBSOCKET_SERVER_CERTIFICATE_THUMBPRINT

# Chama a função principal para iniciar o servidor WebSocket
StartWebSocketServer -ipAddress $ipAddress `
    -port $port `
    -Secure $secure `
    -secretKey $secretKey `
    -certificateThumbprint $certificateThumbprint
