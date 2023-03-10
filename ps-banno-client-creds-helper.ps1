Function Build-SignedJWT {
    # Generate a signed JWT to request an access token for the banno apis
    [CmdletBinding()]
    param (
        # The Client ID generated from the External App in the Banno Developer Settings
        [Parameter(Mandatory=$true)]
        [System.String]
        $clientId,
        # The Full Path to the Private Key File
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            If (Test-Path $_) {
                $true
            }
            Else {
                "Invalid path given: $_"
            }
        })]
        [System.String]
        $privateKeyPath
    )
    Begin {
        #Imports the Dependencies
        Import-Module powershell-jwt
        # -------------------------------------
        $enterpriseOidcTokenUri = 'https://banno.com/a/oidc-provider/api/v0/token'
        # Setting Payload
        $jwtPayload = @{
            jti = [Guid]::NewGuid()
            aud = $enterpriseOidcTokenUri
            sub = $clientId 
        }
        $rsaPrivateKey = Get-Content $privateKeyPath -AsByteStream
        $iss = $clientId
        $exp = ([System.DateTimeOffset]::Now).ToUnixTimeSeconds() + 60 * 1000
    }
    Process {
        Try {
            # Creates a Signed JWT with the $rsaPrivateKey
            $jwt = New-JWT -Algorithm 'RS256' -Issuer $iss -SecretKey $rsaPrivateKey -ExpiryTimestamp $exp -PayloadClaims $jwtPayload
        }
        Catch {
            Write-Error -Message "Token POST Error: " $webRequest.StatusCode
            break
        }  
    }
    End {
        $result = [PSCustomObject]@{
            SignedJWT = $jwt
        }
        return $result
    }
}
Function Get-ClientAssertion {
    # Obtain an access token to call banno apis
    [CmdletBinding()]
    param (
        # The Client ID generated from the External App in the Banno Developer Settings
        [Parameter(Mandatory=$true)]
        [System.String]
        $clientId,
        # The Full Path to the Private Key File
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            If (Test-Path $_) {
                $true
            }
            Else {
                "Invalid path given: $_"
            }
        })]
        [System.String]
        $privateKeyPath
    )
    Begin {
        #Imports the Dependencies
        Import-Module powershell-jwt
        # -------------------------------------
        $enterpriseOidcTokenUri = 'https://banno.com/a/oidc-provider/api/v0/token'

        #Create a Signed JWT
        $clientAssertion = Get-SignedJWT -clientId $clientId -privateKeyPath $privateKeyPath

        #Create the Token Payload
        $tokenPayload = @{
            client_assertion = $clientAssertion.SignedJWT
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            grant_type = 'client_credentials'
            scope = 'openid full'
        }
    }
    Process {
        # Send the request to retrieve access token
        $webRequest = Invoke-WebRequest -Uri $enterpriseOidcTokenUri -Method Post -Headers @{content_type = 'application/x-www-form-urlencoded'} -Body $tokenPayload
        
        If ($webRequest.StatusCode -ne 200) {
            # Status Code is NOT 200/OK
            Write-Error -Message "Token POST Error: " $webRequest.StatusCode
            break
        }

        # Extracts the Access Token from the Response
        $accessToken = ($webRequest.Content) | ConvertFrom-Json
        $accessToken = $accessToken.access_token

        # Decodes the JWT and retrieves the InstitutionId from the decoded Access Token
        $decodedJWT = Confirm-JWT -JWT $accessToken -Key (Get-Content -Path $privateKeyPath -AsByteStream)
        $institutionId = ($decodedJWT.payload).institutionId
        
    }
    End {
        $return = [PSCustomObject]@{
            AccessToken = $accessToken
            InstitutionId = $institutionId
        }
        return $return
    }
}