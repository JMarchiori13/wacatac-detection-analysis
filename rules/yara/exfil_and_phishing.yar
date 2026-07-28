// Artefatos de staging de exfiltracao (doc 14, T1560)
rule Exfil_Staging_Patterns : exfil
{
    meta:
        description = "Nomes e padroes comuns de staging de exfiltracao"
        author = "wacatac-detection-analysis"
    strings:
        $zip_comment = { 50 4B 05 06 }  // fim de ZIP
        $rar = "Rar!" 
        $s1 = "passwords.txt" nocase
        $s2 = "credentials.txt" nocase
        $s3 = "exfil" nocase
    condition:
        ($zip_comment and any of ($s*)) or ($rar and any of ($s*))
}

rule Office_Spawns_Script_Host : childproc
{
    meta:
        description = "Strings tipicas de documento que dispara script (phishing)"
        author = "wacatac-detection-analysis"
    strings:
        $a = "powershell" nocase
        $b = "mshta" nocase
        $c = "wscript.shell" nocase
        $d = "createobject" nocase
    condition:
        2 of them
}
