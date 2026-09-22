$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Invoke-Native([scriptblock]$Block) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = (& $Block 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $saved
    }
    return [pscustomobject]@{ Output = $out; ExitCode = $code }
}

$infoRes = Invoke-Native { docker info }
if ($infoRes.ExitCode -ne 0) {
    Write-Host "Docker is not running. Start Docker Desktop first."
    exit 1
}

$conn = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    $pidStr = ($conn | Select-Object -First 1).OwningProcess
    Write-Host "Port 8000 is already in use (PID $pidStr). Stop that server first."
    exit 1
}

if (-not (Test-Path .env)) {
    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    
    function Get-SecureString {
        $charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        $res = ""
        while ($res.Length -lt 32) {
            $rng.GetBytes($bytes)
            foreach ($b in $bytes) {
                if ($res.Length -ge 32) { break }
                if ($b -lt 248) {
                    $res += $charset[$b % 62]
                }
            }
        }
        return $res
    }
    
    $apiKey = Get-SecureString
    $redisPass = Get-SecureString
    
    "PB_API_KEY=$apiKey`nREDIS_PASSWORD=$redisPass" | Out-File -FilePath .env -Encoding utf8 -NoNewline
    Write-Host "Created .env with a new API key and Redis password. Open .env to see your API key."
}

$envLines = Get-Content .env -ErrorAction SilentlyContinue | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith("#") }
foreach ($line in $envLines) {
    $idx = $line.IndexOf("=")
    if ($idx -gt 0) {
        $key = $line.Substring(0, $idx)
        $val = $line.Substring($idx + 1)
        Set-Item -Path "Env:$key" -Value $val
    }
}

if (-not $env:PB_API_KEY -or $env:PB_API_KEY.Length -lt 16) {
    Write-Host "Error: PB_API_KEY missing or shorter than 16 chars"
    exit 1
}

if (-not $env:REDIS_PASSWORD -or $env:REDIS_PASSWORD.Length -eq 0) {
    Write-Host "Error: REDIS_PASSWORD missing or empty"
    exit 1
}

$env:REDIS_URL = "redis://:" + $env:REDIS_PASSWORD + "@127.0.0.1:16379/0"

function Test-RedisAuth {
    $r = Invoke-Native { docker exec -e "REDISCLI_AUTH=$env:REDIS_PASSWORD" redis redis-cli PING }
    return ($r.Output -match "PONG") -and ($r.Output -notmatch "AUTH failed") -and ($r.Output -notmatch "NOAUTH") -and ($r.Output -notmatch "WRONGPASS")
}

$redisOk = $false
if (Test-RedisAuth) {
    $redisOk = $true
    $noAuthRes = Invoke-Native { docker exec redis redis-cli PING }
    if (($noAuthRes.Output -match "PONG") -and ($noAuthRes.Output -notmatch "NOAUTH")) {
        $redisOk = $false
    }
}

if (-not $redisOk) {
    $null = Invoke-Native { docker rm -f redis }
    
    $runRes = Invoke-Native { docker run -d --name redis -p 127.0.0.1:16379:6379 --tmpfs /data redis:7-alpine redis-server --requirepass $env:REDIS_PASSWORD --appendonly no }
    if ($runRes.ExitCode -ne 0) {
        Write-Host "Docker run failed with exit code $($runRes.ExitCode):"
        $safeOutput = $runRes.Output -replace [regex]::Escape($env:REDIS_PASSWORD), '***' -replace [regex]::Escape($env:PB_API_KEY), '***' -replace [regex]::Escape($env:REDIS_URL), '***'
        Write-Host $safeOutput
        exit 1
    }
    
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        if (Test-RedisAuth) {
            $ready = $true
            break
        }
    }
    
    if (-not $ready) {
        Write-Host "Error: Redis failed to start or authenticate."
        exit 1
    }
}

$buildRes = Invoke-Native { docker build -t pb-net:latest .\pbnet }
if ($buildRes.ExitCode -ne 0) {
    Write-Host $buildRes.Output
    exit 1
} else {
    Write-Host "Tor image ready."
}

$buildRes2 = Invoke-Native { docker build -t pb-browser:latest .\pbbrowser }
if ($buildRes2.ExitCode -ne 0) {
    Write-Host $buildRes2.Output
    exit 1
} else {
    Write-Host "Browser image ready."
}

Write-Host "Dashboard: http://127.0.0.1:8000/"
& .\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
