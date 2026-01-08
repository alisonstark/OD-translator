# Indicators for specific techniques and sub-techniques

POWERSHELL_001_INDICATORS = (
    "downloadstring",
    "downloaddata",
    "invoke-webrequest",
    "invoke-restmethod",
    " iwr ",
    " irm ",
    "frombase64string",
    "add-type",
    "reflection.assembly"
)

CMD_003_INDICATORS = (
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic",
    "ftp "
)
