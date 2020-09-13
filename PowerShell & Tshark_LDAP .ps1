### Function from: https://xkln.net/blog/processing-tshark-streams-with-powershell/ ###

New-Alias -Name tshark -Value "C:\Program Files\Wireshark\tshark.exe"
Function Get-FileName{
    [cmdletbinding()]
    Param ([string]$initialDirectory = "$env:USERPROFILE\desktop")
    Process{

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $initialDirectory
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
    }
}

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
        }

        Write-Output $Packet | Select-Object Time, SrcIP, DstIP, Protocol, SrcPort, DstPort
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

    $capture = tshark -r $pcap -n -l -T ek -e _ws.col.Protocol `
        -e frame.time `
        -e ip.proto `
        -e ip.src `
        -e ip.dst `
        -e tcp.srcport `
        -e tcp.dstport `
        -e udp.srcport `
        -e udp.dstport | 
    ForEach-Object {ProcessPacket $_}

    $count = $capture.count
    $capture = $capture | Sort-Object Time

    foreach ($packet in $capture) {
        if ($packet.srcport -eq 80 -or $packet.dstport -eq 80){$http++}
        elseif ($packet.srcport -eq 135 -or $packet.dstport -eq 135){$DCOM++} 
        elseif ($packet.srcport -eq 443 -or $packet.dstport -eq 443){$https++} 
        elseif ($packet.srcport -eq 137 -or $packet.srcport -eq 138 -or $packet.dstport -eq 137 -or $packet.dstport -eq 138){$NetBios++}  
        elseif ($packet.srcport -eq 53 -or $packet.dstport -eq 53){$DNS++}
        elseif ($packet.srcport -eq 123 -or $packet.dstport -eq 123){$NTP++}
        elseif ($packet.srcport -eq 1900 -or $packet.dstport -eq 1900){$SSDP++}
        elseif ($packet.srcport -eq 445 -or $packet.dstport -eq 445){$SMB++}  
        elseif ($packet.srcport -eq 389 -or $packet.dstport -eq 389){$LDAP++} 
        elseif ($packet.srcport -ge 50000 -or $packet.dstport -ge 50000) { $highport++}
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
    $firsttime = $Time | select -First 1
    $lasttime = $time | select -Last 1

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
}