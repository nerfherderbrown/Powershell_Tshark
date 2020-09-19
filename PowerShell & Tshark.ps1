﻿### Function from: https://xkln.net/blog/processing-tshark-streams-with-powershell/ ###
if ((get-alias tshark -ErrorAction SilentlyContinue).name -ne 'tshark'){New-Alias -Name tshark -Value "C:\Program Files\Wireshark\tshark.exe"}

#### Global Variables to hold converted data ####
Set-Variable -Name capture_stats -Scope Global
Set-Variable -Name capture_http -Scope Global
Set-Variable -Name capture_dns -Scope Global
Set-Variable -Name capture_ldap -Scope Global

function ProcessPacket($InPacketJson) {

    $InPacket = (ConvertFrom-Json $InPacketJson).layers

    if ($InPacket.ip_src) {
        if ($InPacket.tcp_srcport) {$SrcPort = $InPacket.tcp_srcport[0]} elseif ($InPacket.udp_srcport) {$SrcPort = $InPacket.udp_srcport[0]} else {$SrcPort = $null}
        if ($InPacket.tcp_dstport) {$DstPort = $InPacket.tcp_dstport[0]} elseif ($InPacket.udp_dstport) {$DstPort = $InPacket.udp_dstport[0]} else {$DstPort = $null}

        Switch ($InPacket.ip_proto) {
            1 { $Protocol = "ICMP"; break }
            6 { $Protocol = "TCP"; break }
            17 { $Protocol = "UDP"; break }
            default { $Protocol = $InPacket.ip_proto; break }
        }
        $Packet = New-Object -TypeName PSObject -Property @{
            Time = $InPacket.frame_time
            SrcIP   = $InPacket.ip_src[0]
            DstIP   = $InPacket.ip_dst[0]
            Protocol = $Protocol
            SrcPort = $SrcPort
            DstPort = $DstPort
            qry_name = $InPacket.dns_qry_name
            qry_type = $InPacket.dns_qry_type
            qry_a = $InPacket.dns_a
            http_request_method = $InPacket.http_request_method
            http_host = $InPacket.http_host
            http_request_uri = $InPacket.http_request_uri
            http_user_agent = $InPacket.http_user_agent
            http_response_phrase = $InPacket.http_response_phrase
            http_request_version = $InPacket.http_request_version
            http_server = $InPacket.http_server
            http_response_code = $InPacket.http_response_code
        }

        Write-Output $Packet | Select-Object Time, SrcIP, DstIP, Protocol, SrcPort, DstPort, Qry_Name, Qry_Type, Qry_A, http_request_method, http_host, http_request_uri, http_user_agent, http_response_phrase, http_request_version, http_server, http_response_code
    }
}

Function pcap_stats{

    Param(
        [parameter(Mandatory=$true)]
        [String]
        $pcap
        )

    $http = 0
    $NetBios = 0
    $DNS = 0
    $NTP = 0
    $SSDP = 0
    $IGMP = 0
    $SMB = 0
    $ldap = 0
    $dcom = 0
    $highport = 0
    $IPStats = @()

    if ($null -eq $Global:capture_stats){
        $Global:capture_stats = tshark -r $pcap -n -l -T ek `
            -e _ws.col.Protocol `
            -e frame.time `
            -e ip.proto `
            -e ip.src `
            -e ip.dst `
            -e tcp.srcport `
            -e tcp.dstport `
            -e udp.srcport `
            -e udp.dstport | 
        ForEach-Object {ProcessPacket $_}

        $Global:capture_stats = $Global:capture_stats | Sort-Object Time
    }
    $count = $Global:capture_stats.count

    foreach ($packet in $Global:capture_stats) {
        $srcip = $packet.srcip
        $dstip = $packet.dstip

        if ($packet.srcport -eq 80 -or $packet.dstport -eq 80){
            $http++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - HTTP"
        }
        elseif ($packet.srcport -eq 135 -or $packet.dstport -eq 135){
            $DCOM++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - DCOM"
        } 
        elseif ($packet.srcport -eq 443 -or $packet.dstport -eq 443){
            $https++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - HTTPS"
        } 
        elseif ($packet.srcport -eq 137 -or $packet.srcport -eq 138 -or $packet.dstport -eq 137 -or $packet.dstport -eq 138){
            $NetBios++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - NetBios"
        }  
        elseif ($packet.srcport -eq 53 -or $packet.dstport -eq 53){
            $DNS++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - DNS"
        }
        elseif ($packet.srcport -eq 123 -or $packet.dstport -eq 123){
            $NTP++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - NTP"
        }
        elseif ($packet.srcport -eq 1900 -or $packet.dstport -eq 1900){
            $SSDP++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - SSDP"
        }
        elseif ($packet.srcport -eq 445 -or $packet.dstport -eq 445){
            $SMB++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - SMB"
        }  
        elseif ($packet.srcport -eq 389 -or $packet.dstport -eq 389){
            $LDAP++
            $IPStats += "SrcIP: " + $srcip + " - DstIP: " + $dstip + " - LDAP"
        } 
        elseif ($packet.srcport -ge 50000 -or $packet.dstport -ge 50000) {
            $highport++
        }
        else {
            $leftover += $packet.srcport
            $leftover += $packet.dstport
        }
    }
    $leftover = $leftover | Get-Unique | Sort-Object -Descending

    
    $httppercentage = ($http/$count).tostring("P")
    $dcompercentage = ($dcom/$count).tostring("P")
    $httpspercentage = ($https/$count).tostring("P")
    $netbiospercentage = ($netbios/$count).tostring("P")
    $dnspercentage = ($dns/$count).tostring("P")
    $ntppercentage = ($ntp/$count).tostring("P")
    $ssdppercentage = ($ssdp/$count).tostring("P")
    $smbpercentage = ($smb/$count).tostring("P")
    $ldappercentage = ($ldap/$count).tostring("P")
    $time = $capture.Time
    $firsttime = $Time | Select-Object -First 1
    $lasttime = $time | Select-Object -Last 1

    Write-Host "Total Packet Count: $count"
    write-host "Oldest Packet $firsttime"
    Write-Host "newest packet: $lasttime"
    Write-Host "HTTP Packet Count: $http ($httppercentage)"
    Write-Host "HTTPS Packet Count: $https ($httpspercentage)"
    Write-Host "NetBios Packet Count: $netbios ($netbiospercentage)"
    Write-Host "DNS Packet Count: $dns ($dnspercentage)"
    Write-Host "NTP Packet Count: $ntp ($ntppercentage)"
    Write-Host "Simple Service Discovery Protocol Packet Count: $SSDP ($ssdppercentage)"
    Write-Host "DCOM Packet Count: $dcom ($dcompercentage)"
    Write-Host "NTP Packet Count: $ldap ($ldappercentage)"
    Write-Host "NTP Packet Count: $smb ($smbpercentage)"
    write-host "Unmapped:"
    $leftover
    write-host ""
    Write-Host "=============="
    Write-Host "IP Statistics:"
    $IPStats | Group-Object | Select-Object Count, Name | Sort-Object Count -Descending
}

Function pcap_dns{

    Param(
        [parameter(Mandatory=$true)]
        [String]
        $pcap,
        
        [Parameter(Mandatory=$false)]
        [Switch]
        $statistics,

        [Parameter(Mandatory=$false)]
        [Switch]
        $detail
        )

    $dnsstats = @()
    $dnsdetails = @()
    if ($null -eq $Global:capture_dns){
        $Global:capture_dns = tshark -r $pcap -n -l -T ek -Y dns `
            -e _ws.col.Protocol `
            -e frame.time `
            -e ip.proto `
            -e ip.src `
            -e ip.dst `
            -e tcp.srcport `
            -e tcp.dstport `
            -e udp.srcport `
            -e udp.dstport `
            -e dns.qry.name `
            -e dns.qry.type `
            -e dns.a | 
        ForEach-Object {ProcessPacket $_}
        $Global:capture_dns = $Global:capture_dns | Sort-Object Time
    }
    $count = $Global:capture_dns.count

    if ($statistics){
        foreach ($packet in $Global:capture_dns){
            $qname = $packet.qry_name
            $qtype = $packet.qry_type
            $qresult = $packet.qry_a
            if ($null -ne $qresult){$dnsstats += "Query: " + $qname + " - QueryType: " + $qtype + " - Response: " + $qresult}
        }
        $time = $Global:capture_dns.Time
        $firsttime = $Time | Select-Object -First 1
        $lasttime = $time | Select-Object -Last 1

        write-host "DNS Count: $count"
        write-host "Oldest Packet $firsttime"
        Write-Host "newest packet: $lasttime"
        $dnsstats | Group-Object | Select-Object Count, Name | Sort-Object Count -Descending
    }
    elseif ($detail){
        foreach ($packet in $Global:capture_dns){
            $qname = $packet.qry_name
            $qtype = $packet.qry_type
            $qresult = $packet.qry_a
            $time = $packet.time
            if ($null -ne $qresult){$dnsdetails += "Time: " + $time + " - Query: " + $qname + " - QueryType: " + $qtype + " - Response: " + $qresult}
        }
        $dnsdetails | Sort-Object Time
    }
}

Function pcap_http{

    Param(
        [parameter(Mandatory=$true)]
        [String]
        $pcap,
        
        [Parameter(Mandatory=$false)]
        [Switch]
        $statistics,

        [Parameter(Mandatory=$false)]
        [Switch]
        $detail
        )

    $httpstats = @()
    $httpdetails = @()
    if ($null -eq $Global:capture_http){
        $Global:capture_http = tshark -r $pcap -n -l -T ek -Y http `
            -e _ws.col.Protocol `
            -e frame.time `
            -e ip.proto `
            -e ip.src `
            -e ip.dst `
            -e tcp.srcport `
            -e tcp.dstport `
            -e udp.srcport `
            -e udp.dstport `
            -e http.request.method `
            -e http.request.uri `
            -e http.request.version `
            -e http.accept_encoding `
            -e http.user_agent `
            -e http.host `
            -e http.response.version `
            -e http.response.code `
            -e http.response.phrase `
            -e http.server `
            -e http.response.line `
            -e http.file_data |
        ForEach-Object {ProcessPacket $_}

        $Global:capture_http = $Global:capture_http | Sort-Object Time
    }
    $count = $Global:capture_http.count
    if ($statistics){
        foreach ($packet in $Global:capture_http){
            $httphost = $packet.http_host
            $httpresponsecode = $packet.http_response_code
            $httpresponsephrase = $packet.http_response_phrase
            $uri = $packet.http_request_uri
            $method = $packet.http_request_method
            $agent = $packet.http_user_agent
            $src = $packet.srcip
            $servertype = $packet.http_server
            $httpresponse = $httpresponsephrase + "(" + $httpresponsecode + ")"
            if ($null -ne $uri){$httpstats += "Src: " + $src + " Host: " + $httphost + " - URI: " + $uri + " - Method: " + $Method + " - UserAgent: " + $Agent}
            else{$httpstats += "Src: " + $src + " - Response: " + $httpresponse + " - Server Type: " + $servertype}
        }
        write-host "HTTP Packet Count: $count"
        $httpreponsecode_stats
        $httpauthentication_counts
        $filetypes
        $httpURI_stats
        $httpstats
    }
    elseif ($detail){
        foreach ($packet in $Global:capture_http){$packet}
    }
}