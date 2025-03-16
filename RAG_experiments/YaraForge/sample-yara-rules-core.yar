rule SIGNATURE_BASE_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_2 : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Florian Roth (Nextron Systems)"
		id = "37a26def-b360-518e-a4ab-9604a5b39afd"
		date = "2021-03-10"
		modified = "2023-12-05"
		reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/apt_hafnium_log_sigs.yar#L92-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		logic_hash = "13e2e46689bc0e87c3cf13dc2ce213c384afe6c03c21e62a467974a0518c12da"
		score = 65
		quality = 85
		tags = "LOG"

	strings:
		$sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/

	condition:
		$sr1
}
rule SIGNATURE_BASE_Windowscredentialeditor
{
	meta:
		description = "Windows Credential Editor"
		author = "Florian Roth"
		id = "1542c6e4-36b2-5272-85d0-43226869b43e"
		date = "2025-01-25"
		modified = "2025-01-25"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L20-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		logic_hash = "531a0bdc893d89b1c14deee11df95b430051cef07744a15b5d606e1c5378db97"
		score = 90
		quality = 85
		tags = ""
		threat_level = 10

	strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"

	condition:
		all of them
}
rule SIGNATURE_BASE_HKTL_Portscanner_Simple_Jan14
{
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "3e8960ce-0428-51e1-b992-4fa09fee8520"
		date = "2025-01-25"
		modified = "2025-01-25"
		old_rule_name = "PortScanner"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L171-L183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		hash = "b381b9212282c0c650cb4b0323436c63"
		logic_hash = "c69269b227d46b5b970cfc094b3154b0a533b439b8ed492a2059025bc96d17a0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"

	condition:
		all of them
}
rule SIGNATURE_BASE_Domainscanv1_0
{
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "94ead827-8b29-5cb5-82b6-a7ca5087bf7e"
		date = "2025-01-25"
		modified = "2025-01-25"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L185-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
		logic_hash = "b06d902528fee5d1718d0a2984af3314e92e1ec7033c7596f9fb0e51a20eb848"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"

	condition:
		all of them
}
rule SIGNATURE_BASE_HKTL_Moorer_Port_Scanner
{
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "5d8fb83f-bed3-53d2-bd33-2158911dc7c8"
		date = "2025-01-25"
		modified = "2025-01-25"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L204-L217"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
		logic_hash = "248f437964fc6f7836f6b4c87e1f35bb1bac25a1a484cdf1a4065e7efb823b51"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"

	condition:
		all of them
}
rule SIGNATURE_BASE_Netbios_Name_Scanner
{
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "03716e00-a969-5ab5-9be7-e8fc4272e40f"
		date = "2025-01-25"
		modified = "2025-01-25"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L219-L231"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
		logic_hash = "19b40a283b74317fece2f5be0ee3e38227d9631eebbc7efb0ea19056b52630f1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "IconEx"
		$s2 = "soft Visual Stu"
		$s4 = "NBTScanner!y&"

	condition:
		all of them
}
rule SIGNATURE_BASE_Felikspack3___Scanners_Ipscan
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "8360b268-3434-5142-9248-40b7a1589be9"
		date = "2025-01-25"
		modified = "2025-01-25"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L233-L245"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
		logic_hash = "8da10a4536ecea889f29bb3f098518580629bf48eda88db7adfc5f61738ede25"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"

	condition:
		all of them
}
rule SIGNATURE_BASE_Cgisscan_Cgiscan
{
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "60bd5038-a308-55fd-85bb-2c4183f1c951"
		date = "2025-01-25"
		modified = "2025-01-25"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/yara/thor-hacktools.yar#L247-L259"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1d926845269a3ac8de0431da133950390b5cced3/LICENSE"
		hash = "338820e4e8e7c943074d5a5bc832458a"
		logic_hash = "5bd856a77c53616cf78d093462f8b7ca5a5fb0924406a02941d86bdb015a1fbc"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"

	condition:
		all of ( $s* )
}