function Export-MySelfSignedCertificate {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert,
        [System.Security.SecureString] $CertPassword,
        [string] $DnsName,
        [string] $ExportPath
    )

    try {
        if ($null -ne $Cert) {
            $CertPath = Export-PfxCertificate -Cert $Cert -FilePath $ExportPath -Password $CertPassword -Force
            Write-Host "Certificado exportado com sucesso para: $($CertPath)"

            return $CertPath
        } else {
            Write-Host "Falha ao gerar o certificado autoassinado."
            return $null
        }
    } catch {
        Write-Host "Erro ao gerar certificado autoassinado: $($_)"
        return $null
    }
}

function New-PrivateKeyCertificate {
    param (
        [string] $PrivateKey,
        [System.Security.SecureString] $PrivateKeyPassword
    )

    # Converte a chave privada de string para bytes
    $privateKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($PrivateKey)

    # Cria um objeto de chave privada a partir dos bytes
    $privateKeyObj = New-Object System.Security.Cryptography.RSACng
    $privateKeyObj.ImportEncryptedPkcs8PrivateKey($privateKeyBytes, $PrivateKeyPassword)

    return $privateKeyObj
}

function New-MySelfSignedCertificate {
    param (
        [string] $DnsName,
        [string] $CertStoreLocation,
        [string] $CertName,
        [string] $PrivateKey,
        [System.Security.SecureString] $PrivateKeyPassword,
        [DateTime] $notAfter
    )

    try {
        $PrivateKeyCreated = New-PrivateKeyCertificate -PrivateKey $PrivateKey -PrivateKeyPassword $PrivateKeyPassword
        # Gera o certificado com a chave privada associada
        $cert = New-SelfSignedCertificate -DnsName $dnsName -CertStoreLocation $certStoreLocation -FriendlyName $certName -KeyExportPolicy Exportable -KeyProtection UseProvidedPassword -Key $PrivateKeyCreated -KeyPassword $PrivateKeyPassword -KeyUsage KeyEncipherment,DataEncipherment,DigitalSignature -Type SSLServerAuthentication -NotAfter $notAfter
    } catch {
        Write-Host "Erro ao gerar certificado autoassinado: $($_)"
    }

    return $cert
}

function Set-MySelfSignedCertificate {
    param (
        [string] $DnsName,
        [string] $CertName,
        [string] $CertStoreLocation,
        [DateTime] $notAfter,
        [string] $ExportPath,
        [System.Security.SecureString] $CertPassword
    )

    try {
        $Cert = New-MySelfSignedCertificate -DnsName $DnsName -CertName $CertName -CertStoreLocation $CertStoreLocation -notAfter $notAfter

        Export-MySelfSignedCertificate -Cert $Cert -ExportPath $ExportPath -CertPassword $CertPassword -DnsName $DnsName | Out-Null
    } catch {
        Write-Host "Falha ao gerar o certificado autoassinado."
    }
}


# Path to the JSON file
$jsonFilePath = "./CertConfig.json"

# Read and parse the JSON file
$jsonData = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json

# Assign values from JSON
$dnsName = $jsonData.dnsName
$certName = $jsonData.certName
$certPassword = $jsonData.certPassword
$securePassword = ConvertTo-SecureString -String $certPassword -AsPlainText -Force
$exportPath = $jsonData.exportPath
$certStoreLocation = $jsonData.certStoreLocation
$notAfter = (Get-Date).AddYears(1)

Set-MySelfSignedCertificate -DnsName $dnsName -CertName $certName -CertPassword $securePassword -ExportPath $exportPath -CertStoreLocation $certStoreLocation -notAfter $notAfter
