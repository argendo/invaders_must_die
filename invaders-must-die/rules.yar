rule SQL_Injection {
    strings:
        $sql_injection = "'; DROP TABLE users; --"

    condition:
        $sql_injection
}
rule XSS_Attack {
    strings:
        $xss_payload = "<script>"

    condition:
        $xss_payload
}
rule AnimeDetector {
    strings:
        $anime_str = "anime"

    condition:
        $anime_str
}

