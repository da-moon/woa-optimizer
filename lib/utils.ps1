# aux funcs
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}
Function WaitForKey {
	Write-Host
	info "Press any key to restart..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
}
Function Restart {
	info "Restarting..."
	Restart-Computer
}

function pwd($path) {
    "$($myinvocation.psscriptroot)\$path" 
} 
function Confirm-Aria2 {
    if ((Get-Command "aria2c" -ErrorAction SilentlyContinue) -eq $null) 
    { 
        warn "Unable to find aria2c in your PATH"
        info "downloading aria2 with scoop"
        scoop install aria2
    }
}
function aria2_dl($url,$dir,$file) {
    Confirm-Aria2
    aria2c -k 1M -c -j16 -x16 --dir="$dir" --out="$file" "$url"
}
function dl($url,$to) {
    $wc = New-Object Net.Webclient
    $wc.downloadFile($url,$to)
}

# download optimizer script repo
function get_optimizer_script($dir) {
    $zipurl = 'https://github.com/da-moon/woa-optimizer/archive/master.zip'
    $zipfile = "$dir\woa-optimizer.zip"
    Write-Output 'Downloading scoop...'
    dl $zipurl $zipfile
    
    Write-Output 'Extracting...'
    Add-Type -Assembly "System.IO.Compression.FileSystem"
    [IO.Compression.ZipFile]::ExtractToDirectory($zipfile, "$dir\_tmp")
    Copy-Item "$dir\_tmp\*master\*" $dir -Recurse -Force
    Remove-Item "$dir\_tmp", $zipfile -Recurse -Force
} 
function getopt($argv, $shortopts, $longopts) {
    $opts = @{}; $rem = @()

    function err($msg) {
        $opts, $rem, $msg
    }

    function regex_escape($str) {
        return [regex]::escape($str)
    }

    # ensure these are arrays
    $argv = @($argv)
    $longopts = @($longopts)

    for($i = 0; $i -lt $argv.length; $i++) {
        $arg = $argv[$i]
        if($null -eq $arg) { continue }
        # don't try to parse array arguments
        if($arg -is [array]) { $rem += ,$arg; continue }
        if($arg -is [int]) { $rem += $arg; continue }
        if($arg -is [decimal]) { $rem += $arg; continue }

        if($arg.startswith('--')) {
            $name = $arg.substring(2)

            $longopt = $longopts | Where-Object { $_ -match "^$name=?$" }

            if($longopt) {
                if($longopt.endswith('=')) { # requires arg
                    if($i -eq $argv.length - 1) {
                        return err "Option --$name requires an argument."
                    }
                    $opts.$name = $argv[++$i]
                } else {
                    $opts.$name = $true
                }
            } else {
                return err "Option --$name not recognized."
            }
        } elseif($arg.startswith('-') -and $arg -ne '-') {
            for($j = 1; $j -lt $arg.length; $j++) {
                $letter = $arg[$j].tostring()

                if($shortopts -match "$(regex_escape $letter)`:?") {
                    $shortopt = $matches[0]
                    if($shortopt[1] -eq ':') {
                        if($j -ne $arg.length -1 -or $i -eq $argv.length - 1) {
                            return err "Option -$letter requires an argument."
                        }
                        $opts.$letter = $argv[++$i]
                    } else {
                        $opts.$letter = $true
                    }
                } else {
                    return err "Option -$letter not recognized."
                }
            }
        } else {
            $rem += $arg
        }
    }

    $opts, $rem
}