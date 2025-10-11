# KernelModulesScanner.ps1
# REQUIRES: Run as Administrator

param(
    [string]$OutputPath = ".\KernelScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$DeepScan = $false
)

# Sprawdzenie uprawnień administratora
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "`n❌ This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "   Please run PowerShell as Administrator and try again.`n" -ForegroundColor Yellow
    exit 1
}

# Funkcja do ładnego wyświetlania banneru
function Show-Banner {
    Clear-Host
    Write-Host "`n"
    Write-Host " _   _    _    ___ ___ ___ " -ForegroundColor Cyan
    Write-Host "| \ | |  / \  | _ ) __/ __|" -ForegroundColor Cyan
    Write-Host "|  \| | / _ \ | _ \ _| (__ " -ForegroundColor Cyan
    Write-Host "|_|\_|/_/ \_\|___/_| \___|" -ForegroundColor Cyan
    Write-Host "`n" 
    Write-Host "            🛡️  KERNEL MODULES SCANNER 🛡️" -ForegroundColor Yellow
    Write-Host "`n" 
    Write-Host "                MADE BY NACIO" -ForegroundColor Green
    Write-Host "         Discord: discord.gg/pcchecking" -ForegroundColor Magenta
    Write-Host "`n" 
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "`n"
}

# Funkcja do animowanego ładowania
function Show-Loading {
    param(
        [string]$Message = "Loading",
        [int]$Seconds = 3
    )
    
    $cursorTop = [Console]::CursorTop
    $frames = @('⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷')
    
    for ($i = 0; $i -lt $Seconds * 8; $i++) {
        $frame = $frames[$i % $frames.Length]
        Write-Host "`r$frame $Message..." -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds 125
    }
    Write-Host "`r✅ $Message completed!" -ForegroundColor Green
}

# Funkcja do progress bara
function Show-ProgressBar {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [bool]$Completed = $false
    )
    
    if ($Completed) {
        Write-Progress -Activity $Activity -Status "Completed!" -Completed
        Write-Host "✅ $Activity finished!" -ForegroundColor Green
    } else {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}

# Główne funkcje skanowania
function Get-AllSystemDrivers {
    $drivers = @()
    
    Write-Host "🔍 Scanning for system drivers (.sys files)..." -ForegroundColor Yellow
    
    # Lokalizacje gdzie są przechowywane sterowniki
    $driverPaths = @(
        "$env:windir\System32\drivers",
        "$env:windir\System32\DriverStore\FileRepository",
        "$env:windir\SysWOW64\drivers"
    )
    
    $counter = 0
    foreach ($path in $driverPaths) {
        if (Test-Path $path) {
            try {
                $sysFiles = Get-ChildItem -Path $path -Filter "*.sys" -ErrorAction SilentlyContinue
                foreach ($file in $sysFiles) {
                    $counter++
                    Show-ProgressBar -Activity "Finding .sys files" -Status "Found: $($file.Name)" -PercentComplete (($counter % 100))
                    
                    try {
                        $versionInfo = $file.VersionInfo
                        $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                        
                        $drivers += [PSCustomObject]@{
                            ModuleName = $file.Name
                            FilePath = $file.FullName
                            Size = "$([math]::Round($file.Length/1KB, 2)) KB"
                            Description = $versionInfo.FileDescription
                            Company = $versionInfo.CompanyName
                            FileVersion = $versionInfo.FileVersion
                            ProductVersion = $versionInfo.ProductVersion
                            TimeCreated = $file.CreationTime
                            TimeModified = $file.LastWriteTime
                            IsSigned = if ($signature) { $signature.Status -eq "Valid" } else { $false }
                            SignatureStatus = if ($signature) { $signature.Status.ToString() } else { "NotSigned" }
                            CertificateSubject = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "Unknown" }
                        }
                    } catch {
                        # Pomijamy pliki do których nie mamy dostępu
                    }
                }
            } catch {
                Write-Host "⚠️  Cannot access path: $path" -ForegroundColor Yellow
            }
        }
    }
    
    Show-ProgressBar -Activity "Finding .sys files" -Completed $true
    return $drivers
}

function Get-LoadedKernelModules {
    Write-Host "🔍 Scanning loaded kernel modules..." -ForegroundColor Yellow
    $loadedModules = @()
    
    try {
        # Pobieranie załadowanych modułów przez system
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        $totalProcesses = $processes.Count
        $currentProcess = 0
        
        foreach ($process in $processes) {
            $currentProcess++
            $percentComplete = [math]::Round(($currentProcess / $totalProcesses) * 100)
            
            Show-ProgressBar -Activity "Scanning process modules" -Status "Process: $($process.ProcessName) ($currentProcess/$totalProcesses)" -PercentComplete $percentComplete
            
            try {
                foreach ($module in $process.Modules) {
                    if ($module.FileName -like "*.sys") {
                        $loadedModules += [PSCustomObject]@{
                            ProcessName = $process.ProcessName
                            PID = $process.Id
                            ModuleName = $module.ModuleName
                            FilePath = $module.FileName
                            BaseAddress = "0x" + $module.BaseAddress.ToString("X16")
                            MemorySize = "$([math]::Round($module.ModuleMemorySize/1KB, 2)) KB"
                            IsCurrentlyLoaded = $true
                        }
                    }
                }
            } catch {
                # Niektóre procesy systemowe nie pozwalają na dostęp do modułów
            }
        }
        
        Show-ProgressBar -Activity "Scanning process modules" -Completed $true
        
    } catch {
        Write-Host "❌ Error scanning loaded modules: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $loadedModules
}

function Assess-DriverRisk {
    param($Driver)
    
    $riskLevel = "Low"
    $flags = @()
    
    # Heuristic analysis
    if (-not $Driver.IsSigned) {
        $riskLevel = "Medium"
        $flags += "Unsigned"
    }
    
    if ($Driver.FilePath -like "*\temp\*" -or $Driver.FilePath -like "*\appdata\*") {
        $riskLevel = "High"
        $flags += "SuspiciousPath"
    }
    
    if ([string]::IsNullOrWhiteSpace($Driver.Company)) {
        $riskLevel = "Medium"
        $flags += "NoCompanyInfo"
    }
    
    if ($Driver.Description -like "*test*" -or $Driver.Description -like "*unknown*") {
        $riskLevel = "Medium"
        $flags += "SuspiciousDescription"
    }
    
    return @{
        ThreatLevel = $riskLevel
        SecurityFlags = ($flags -join " | ")
    }
}

# 🚀 GŁÓWNE WYKONANIE SKRYPTU
Show-Banner

Write-Host "⏳ Starting comprehensive kernel scan..." -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

# Skanowanie wszystkich driverów .sys
Show-Loading -Message "Initializing scanner" -Seconds 2

$allDrivers = Get-AllSystemDrivers
$loadedModules = Get-LoadedKernelModules

Write-Host "`n📊 SCAN RESULTS:" -ForegroundColor Green
Write-Host "   • Total .sys files found: $($allDrivers.Count)" -ForegroundColor White
Write-Host "   • Currently loaded modules: $($loadedModules.Count)" -ForegroundColor White

# Analiza bezpieczeństwa
Write-Host "`n🔒 Analyzing security..." -ForegroundColor Yellow
Show-Loading -Message "Security analysis" -Seconds 2

$results = @()
$counter = 0

foreach ($driver in $allDrivers) {
    $counter++
    $percentComplete = [math]::Round(($counter / $allDrivers.Count) * 100)
    
    Show-ProgressBar -Activity "Security Analysis" -Status "Analyzing: $($driver.ModuleName)" -PercentComplete $percentComplete
    
    $riskAssessment = Assess-DriverRisk -Driver $driver
    $isLoaded = ($loadedModules | Where-Object { $_.FilePath -eq $driver.FilePath }).Count -gt 0
    
    $results += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ModuleName = $driver.ModuleName
        FilePath = $driver.FilePath
        Size = $driver.Size
        Description = $driver.Description
        Company = $driver.Company
        FileVersion = $driver.FileVersion
        ProductVersion = $driver.ProductVersion
        TimeCreated = $driver.TimeCreated
        TimeModified = $driver.TimeModified
        IsSigned = $driver.IsSigned
        SignatureStatus = $driver.SignatureStatus
        CertificateSubject = $driver.CertificateSubject
        IsCurrentlyLoaded = $isLoaded
        ThreatLevel = $riskAssessment.ThreatLevel
        SecurityFlags = $riskAssessment.SecurityFlags
    }
}

Show-ProgressBar -Activity "Security Analysis" -Completed $true

# Eksport do CSV
Write-Host "`n💾 Exporting results to CSV..." -ForegroundColor Cyan
try {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "✅ Successfully exported to: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "❌ Error exporting to CSV: $($_.Exception.Message)" -ForegroundColor Red
}

# Podsumowanie
Write-Host "`n" + "=" * 50 -ForegroundColor Cyan
Write-Host "📈 SCAN SUMMARY" -ForegroundColor Green
Write-Host "=" * 50 -ForegroundColor Cyan

$totalDrivers = $results.Count
$unsignedCount = ($results | Where-Object { $_.IsSigned -eq $false }).Count
$highRiskCount = ($results | Where-Object { $_.ThreatLevel -eq "High" }).Count
$loadedCount = ($results | Where-Object { $_.IsCurrentlyLoaded -eq $true }).Count

Write-Host "   Total Drivers Scanned: $totalDrivers" -ForegroundColor White
Write-Host "   Currently Loaded: $loadedCount" -ForegroundColor $(if ($loadedCount -gt 0) { "Cyan" } else { "White" })
Write-Host "   Unsigned Drivers: $unsignedCount" -ForegroundColor $(if ($unsignedCount -gt 0) { "Red" } else { "Green" })
Write-Host "   High Risk Drivers: $highRiskCount" -ForegroundColor $(if ($highRiskCount -gt 0) { "Red" } else { "Green" })

if ($highRiskCount -gt 0) {
    Write-Host "`n⚠️  WARNING: High risk drivers detected!" -ForegroundColor Red
    $highRiskDrivers = $results | Where-Object { $_.ThreatLevel -eq "High" }
    foreach ($driver in $highRiskDrivers) {
        Write-Host "   • $($driver.ModuleName) - $($driver.SecurityFlags)" -ForegroundColor Yellow
    }
}

Write-Host "`n🎯 Scan completed at: $(Get-Date)" -ForegroundColor Green
Write-Host "   Thank you for using NACIO's Kernel Scanner!`n" -ForegroundColor Magenta

# Otwórz folder z wynikami
if (Test-Path $OutputPath) {
    $openFolder = Read-Host "📂 Open results folder? (Y/N)"
    if ($openFolder -eq 'Y' -or $openFolder -eq 'y') {
        Invoke-Item (Split-Path $OutputPath -Parent)
    }
}