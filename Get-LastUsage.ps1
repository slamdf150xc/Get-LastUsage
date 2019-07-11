$baseURI = "https://components.cyberarkdemo.com"
$acctName = "Account name to check on"
$acctAddy = "Account address to check on"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function EPVLogin($user, $pass) {
	$data = @{
		username=$user
		password=$pass
	}

	$loginData = $data | ConvertTo-Json

	Try {
		Write-Host "Logging into EPV as $user..." -NoNewLine
		
		$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/API/Auth/LDAP/Logon" -Method POST -Body $loginData -ContentType 'application/json'
		
		Write-Host "Success!" -ForegroundColor Green
	} Catch {
		ErrorHandler "Login was not successful" $_.Exception.Message $_ $false
	}
	return $ret
}

Function EPVLogoff {
	Try {
		Write-Host "Logging off..." -NoNewline
		
		Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff" -Method POST -Headers $header -ContentType 'application/json'
		
		Write-Host "Logged off!" -ForegroundColor Green
	} Catch {
		ErrorHandler "Log off was not successful" $_.Exception.Message $_ $false
	}
}

Function Get-Accounts {
    param (
        $acctName,
        $acctAddy
    )
    try {
        Write-Host "Searching for accounts..." -NoNewline

        $ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/api/Accounts?search=$acctName,%20$acctAddy" -Method Get -ContentType "application/json" -Headers $header

        Write-Host "Success!"-ForegroundColor Green

        return $ret.value.ID
    }
    catch {
        ErrorHandler "Get-Accounts was not successful" $_.Exception.Message $_ $true
    }
}

function Get-AccountActivity {
    param (
        $acctID
    )
    $ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Accounts/$acctID/Activities" -Method Get -ContentType "application/json" -Headers $header

    return $ret
}

function ErrorHandler {
    param (
        $message,
        $exceptionMessage,
        $fullMessage,
        $logoff
    )
    Write-Host "---------- Error ----------"    
	Write-Host $message -ForegroundColor Red
	Write-Host "Exception Message:"
	Write-Host $exceptionMessage -ForegroundColor Red
	Write-Host "Full Error Message:"
	Write-Host $fullMessage -ForegroundColor Red
    Write-Host "Stopping script" -ForegroundColor Yellow
    Write-Host "-------- End Error --------"    
	
	If ($logoff) {
		EPVLogoff
	}
	Exit 1
}

Write-Host "Please log into EPV"
$user = Read-Host "EPV User Name"
$securePassword = Read-Host "Password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$unsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$login = EPVLogin $user $unsecurePassword
$unsecurePassword = ""

$script:header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$script:header.Add("Authorization", $login)

$acctID = Get-Accounts -acctName $acctName -acctAddy $acctAddy

$acctActivity = Get-AccountActivity $acctID

$lastUsed = $acctActivity.GetAccountActivitiesResult.Time[0]

Write-Host "The account $acctName was lased used at $lastUsed"

EPVLogoff
