# Function to check if the script is running as Administrator
function Is-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]Administrator)
}

# Function to calculate MD5 hash of a file
function Get-FileMD5 {
    param([string]$filePath)
    $hashAlgorithm = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    $fileStream = [System.IO.File]OpenRead($filePath)
    $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
    $fileStream.Close()
    return [BitConverter]ToString($hashBytes) -replace '-'
}

# Function to scan files in the system
function Scan-Files {
    $firstFileName = credits.txt
    $firstFileSize = 46592
    $firstFileMD5 = 84c888920bcaf7f00fc9ce0d7ff2d579
    $firstDetectionMessage = Sacred Private found credits.txt was found in 

    $msvcpFileName = MSVCP122.dll
    $msvcpDetectionMessage = Sacred Public found MSVCP122.dll was found in 

    # Scan all logical drives
    $drives = Get-WmiObject Win32_LogicalDisk  Where-Object { $_.DriveType -eq 3 }

    foreach ($drive in $drives) {
        $driveLetter = $drive.DeviceID
        Write-Host Scanning drive $driveLetter...

        # Recursively scan all files in the drive
        Get-ChildItem -Path $driveLetter -Recurse -ErrorAction SilentlyContinue  ForEach-Object {
            $filePath = $_.FullName

            # Check for credits.txt (Sacred Private)
            if ($_.Name -eq $firstFileName) {
                if ($_.Length -eq $firstFileSize -and (Get-FileMD5 -filePath $filePath) -eq $firstFileMD5) {
                    Write-Host $firstDetectionMessage$filePath
                }
            }

            # Check for MSVCP122.dll (Sacred Public)
            if ($_.Name -eq $msvcpFileName) {
                Write-Host $msvcpDetectionMessage$filePath
            }
        }
    }
}

# Main script execution
if (-not (Is-Admin)) {
    Write-Host This application needs to be run as an administrator.
    Write-Host Please restart the application with administrator privileges.
    exit
}

# Display the title and prompt the user
Write-Host Sacred detector By grin
$userResponse = Read-Host Do you want to check for sacred (YESNO)

if ($userResponse -eq YES -or $userResponse -eq yes) {
    Scan-Files
} else {
    Write-Host Scan aborted.
}
