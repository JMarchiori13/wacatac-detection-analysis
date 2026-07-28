// Formato de token do Discord (doc: windows-credential-paths 04)
rule Discord_User_Token : token
{
    meta:
        description = "Token de usuario do Discord em memoria ou arquivo"
        author = "wacatac-detection-analysis"
    strings:
        $re = /[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/
    condition:
        $re
}

rule Discord_MFA_Token : token
{
    meta:
        description = "Token Discord com prefixo mfa"
        author = "wacatac-detection-analysis"
    strings:
        $re = /mfa\.[A-Za-z0-9_-]{84}/
    condition:
        $re
}
