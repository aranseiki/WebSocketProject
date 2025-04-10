# Chave privada em formato PEM (exemplo)
$privateKey = @"
-----BEGIN PRIVATE KEY-----
404bfe08-657c-11ee-8c99-0242ac120002
-----END PRIVATE KEY-----
"@

# Senha da chave privada
$privateKeyPassword = "sua-senha"
# Converta a chave privada de string para SecureString
$privateKeyPasswordSecure = ConvertTo-SecureString -String $privateKeyPassword -AsPlainText -Force

# Crie o certificado usando a chave privada
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DnsName "localhost" -KeySpec Signature

# Exporte o certificado em um arquivo PFX temporário
$certPath = "C:\dev\WebSocketServer\TempCert.pfx"
$certPassword = "sua-senha"
$cert | Export-PfxCertificate -FilePath $certPath -Password (ConvertTo-SecureString -String $certPassword -AsPlainText -Force)

# Carregue o certificado e a chave privada em uma variável
$certWithPrivateKey = Import-PfxCertificate -FilePath $certPath -CertStoreLocation "Cert:\LocalMachine\My" -Exportable -Password $privateKeyPasswordSecure

Write-Host "Certificado exportado com sucesso para: $($certPath)"
