function abort($msg, [int] $exit_code=1) { 
    write-host $msg -f red
    exit $exit_code
}
function error($msg) { 
    write-host "[ERROR] $msg" -f darkred 
}
function warn($msg) {
    write-host "[WARN]  $msg" -f darkyellow 
}
function info($msg) {  
    write-host "[INFO]  $msg" -f darkcyan 
}
function debug($msg) {  
    write-host "[DEBUG]  $msg" -f darkgray 
}
function success($msg) { 
    write-host  "[DONE] $msg" -f darkgreen 
}
