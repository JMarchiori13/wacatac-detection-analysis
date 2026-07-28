// Heuristica de PE empacotado (doc 03, T1027.002)
// Triagem, nao bloqueio: NSIS e instaladores legítimos disparam.
rule PE_High_Entropy_Section : packer
{
    meta:
        description = "PE com secao executavel de entropia alta, tipico de packer"
        author = "wacatac-detection-analysis"
        reference = "docs/03-evasion-categories.md"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and
        for any i in (0..10):
            (uint32(0x3C) < 0x400 and
             math.entropy(0x400, 0x2000) > 7.2)
}

rule UPX_Signature : packer
{
    meta:
        description = "Marcadores do packer UPX"
        author = "wacatac-detection-analysis"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        2 of them
}

rule Few_Imports_GetProcAddress : packer
{
    meta:
        description = "Poucos imports com resolucao dinamica de API"
        author = "wacatac-detection-analysis"
    strings:
        $a = "LoadLibraryA" nocase
        $b = "LoadLibraryW" nocase
        $c = "GetProcAddress" nocase
        $d = "VirtualAlloc" nocase
    condition:
        ($a or $b) and $c and $d
}
