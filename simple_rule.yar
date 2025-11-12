rule suspicious_http_tools {
  meta:
    author = "matsung"
    description = "Detect wget/curl/password/token strings in memory strings"
    date = "2025-11-11"

  strings:
    $wget = "wget " ascii nocase
    $curl = "curl " ascii nocase
    $pass = "password" ascii nocase
    $bearer = "Authorization: Bearer " ascii nocase

  condition:
    any of ($wget, $curl, $pass, $bearer)
}
