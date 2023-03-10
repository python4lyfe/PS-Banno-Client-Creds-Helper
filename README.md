# PS-Banno-Client-Creds-Helper

This is a PowerShell version of the [JavaScript Helper Utility](https://github.com/Banno/banno-client-creds-helper). I created these functions so I could use the Banno API for RPA Automations.

## Getting Started


- Install the latest version of PowerShell (PWSH):
```PowerShell
Invoke-Expression "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
```

- Ensure your PowerShell (PWSH) version is at least v6.2:
```PowerShell
PS C:\Current\Working\Directory> $PSVersionTable
```

- Install the [powershell-jwt](https://github.com/Nucleware/powershell-jwt) Module within PWSH:
```PowerShell
PS C:\Current\Working\Directory> Install-Module -Name powershell-jwt -Scope AllUsers
```

## Usage

*Disclaimer: You must run this in the updated PowerShell (PWSH). These will not work with the built-in version of PowerShell in Windows (v5.1)*

- You can Dot Source them:
```PowerShell
PS C:\Current\Working\Directory> . C:\Path\To\Script\ps-banno-client-creds-helper.ps1
```
- You can add the command you wish to use at the bottom of the script, save, right-click, and run with PowerShell 7
- You can add the command you wish to use at the bottom of the script, save, then execute the command:
```PowerShell
PS C:\Current\Working\Directory> pwsh ps-banno-client-creds-helper.ps1
```
- You can split them up into your own scripts

The world is your oyster!

### Using the Functions

`Build-SignedJWT` Creates a Signed JWT, signing with your clientId, privateKeyPath, and the other payload requirements from the original [JavaScript Helper Utility](https://github.com/Banno/banno-client-creds-helper):
```PowerShell
Build-SignedJWT -clientId "00000000-0000-0000-0000-000000000000" -privateKeyPath "C:\Path\To\Keys\private_key.pem"
```
Returns `PSCustomObject`:
```PowerShell
SignedJWT
----------
[Base64EncryptedString]
```

`Get-ClientAssertion` will create a Signed JWT ***AND*** retrieve an Access (Bearer) Token:
```PowerShell
Get-ClientAssertion -clientId "00000000-0000-0000-0000-000000000000" -privateKeyPath "C:\Path\To\Keys\private_key.pem"
```
Returns `PSCustomObject`:
```PowerShell
AccessToken                             InstitutionId
---------------                         ---------------
[Base64EncryptedString]                 00000000-0000-0000-0000-000000000000
```
This one is the money here. This returns everything required for you to make API calls with the [Banno Admin API](https://jackhenry.dev/open-api-docs/admin-api/).

## Changelog


## Contributing and Support

🐞 If the code doesn't perform as expected, raise a GitHub issue. Specify the expected behaviour and the actual output/error message. Make sure you're using the latest published version of the script and that you've met the initial requirements.

🛠️ Pull requests are welcome if you want to add functionality.