# 工具简介
"""
WPScan工具是一款免费的、用于非商业用途的黑盒WordPress安全扫描器，专为安全专业人员和博客维护者编写，用于测试其网站的安全性。WPScan工具中包含28794个WordPress漏洞的数据库。
Homepage: https://wpscan.com/
GitHub: https://github.com/wpscanteam/wpscan
Type: IMAGE-BASED
Version: v3.8.22
"""
# 导入工具依赖包，分别用于启动工具镜像、将结果数据写入数据库、改写 ENTRYPOINT 和解析注释
from levrt import Cr, ctx, remote, annot
from levrt.annot.cats import Attck, BlackArch
@annot.meta(desc="wpscan 原生调用", params=[annot.ARGV])
def raw(argv:list[str]) -> Cr:
    """
    wpscan 原生调用
    ```
    await wpscan.raw(["--url", "https://www.example.com"])
    ```
    """
    @remote
    def entry(argv):
        import subprocess, sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        import xmltodict
        subprocess.run(['/home/nmap/nmap', '-oX', '/tmp/typical.xml', *argv], text=True)
        ip_info = {
            'res' : ''
        }
        try:
            with open('/tmp/typical.xml', 'r') as f:
                ip_info['res'] = xmltodict.parse(f.read())
        except Exception:
            pass
        ctx.update(ip_info)
    return Cr(".whtcjdtc2008.nmap:v1.5", entry=entry(argv))
@annot.meta(
    desc = "nmap 典型调用，启用-A选项（操作系统探测、脚本扫描及路由追踪），-T4选项（快速执行）",
    params = [annot.Param("ip", "待扫描的目标域名或ip", holder="lev.zone")]
)
def typical(ip:str) -> Cr:
    """
    nmap 典型调用，启用-A选项（操作系统探测、脚本扫描及路由追踪），-T4选项（快速执行）
    ```
    await nmap.typical("192.168.1.1/24")
    ```
    """
    @remote
    def entry(ip):
        import subprocess, sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        import xmltodict
        subprocess.run(['/home/nmap/nmap', '-A', '-T4', '-oX', '/tmp/typical.xml', ip])
        ip_info = {
            'res' : ''
        }
        try:
            with open('/tmp/typical.xml', 'r') as f:
                ip_info['res'] = xmltodict.parse(f.read())
        except Exception:
            pass
        # save data into mongo
        ctx.update(ip_info)
        # print(ip_info)
    return Cr(".whtcjzadtc2008.nmap:v1.5", entry=entry(ip))
    # return Cr("1c0bc38f4b85", entry=entry(ip))
@annot.meta(
    desc = "nmap 判断目标是否存活，启用-sn选项（关闭端口扫描），使用TCP SYN/ACK、UDP、ICMP及IP技术进行目标存活状态探测",
    params = [annot.Param("ip", "待扫描的目标域名或ip", holder="lev.zone"),
              annot.Param('disable_arp_ping', '是否开启ARP或者ipv6的Neighbor Discovery（默认否）'),
              annot.Param('discovery_ignore_rst', '是否忽略TCP reset(RST) 回复（默认否），忽略该报文可以避免防火墙返回的RST影响存活判断')]
)
def alive(ip: list[str], disable_arp_ping: bool = False, discovery_ignore_rst: bool = False) -> Cr:
    """
    TCP SYN 可用于突破高端防火墙的包状态检测，TCP ACK 可用于突破防火墙的SYN包拦截， UDP 用于突破TCP协议拦截
    TCP SYN 覆盖的端口 : 25, 80, 443, 1080, 3306, 6379, 9999, 10000
    TCP ACK 覆盖的端口 : 25, 80, 443, 1080, 3306, 6379, 9999, 10000
    UDP Ping 覆盖的端口 : 34567, 45678, 56789
    SCTP INIT Ping 覆盖的端口 : 22, 80, 139, 443
    ICMP 覆盖的请求 : ICMP echo, ICMP timestamp and ICMP address
    IP 协议覆盖的协议号 : ICMP(protocol 1), IGMP(protocol 2), IP-in-IP(protocol 4), TCP(protocol 6), UDP(protocol 17), SCTP(protocol 132)
    ```
    await nmap.alive(["192.168.1.1/24"])
    ```
    """
    @remote
    def entry(ip):
        import subprocess
        import sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        import xmltodict
        command = ['/home/nmap/nmap', '-sn', '-PS25,80,443,1080,3306,6379,9999,10000', '-PA25,80,443,1080,3306,6379,9999,10000', '-PU34567,45678,56789', '-PY22,80,139,443', '-PE', '-PP', '-PM', '-PO1,2,4,6,17,132']
        if disable_arp_ping:
            command.append('--disable-arp-ping')
        if discovery_ignore_rst:
            command.append('--discovery-ignore-rst')
        command.append('-T4')
        command.append('-n')
        command.append('-oX')
        command.append('/tmp/alive.xml')
        command += ip
        subprocess.run(command)
        res = ''
        try:
            with open('/tmp/alive.xml', 'r') as f:
                res = xmltodict.parse(f.read())
        except Exception:
            pass
        ip_info = {
            'res' : res
        }
        print(ip_info)
        ctx.update(ip_info)
    return Cr(".whtcjdtc2008.nmap:v1.5", entry=entry(ip))
@annot.meta(
    desc = "nmap 路由追踪，启用--traceroute功能，可选TCP SYN/ACK、UDP、ICMP及IP技术进行探测",
    params = [
        annot.Param("ip", "待扫描的目标域名或ip", holder="lev.zone"),
        annot.Param("by_tcp_syn", "使用TCP SYN方式（Docker Desktop for Mac不支持此功能）"),
        annot.Param("by_tcp_ack", "使用TCP ACK方式（Docker Desktop for Mac不支持此功能）"),
        annot.Param("by_udp", "使用UDP方式"),
        annot.Param("by_sctp", "使用SCTP方式"),
        annot.Param("by_icmp", "使用ICMP方式（推荐方式）"),
        annot.Param("by_ip", "使用IP Protocol方式"),
    ]
)
def traceroute(ip: str, by_tcp_syn: bool = False, by_tcp_ack: bool = False, by_udp: bool = False, by_sctp: bool = False, by_icmp: bool = True, by_ip: bool = False) -> Cr:
    """
    Nmap traceroute 使用TTL机制进行扫描
    备注：
    1. TCP选项不适用于Docker Desktop on Mac；（据https://github.com/moby/vpnkit/issues/194显示，目前Docker Desktop on Mac仅对UDP及ICMP进行了TTL支持，TCP类型目前暂不可用）
    2. 由于nmap的工作机制，扫描选项仅可启用一项，多选只会随机选取一种方式进行，并不会进行所有方式的扫描，如需启用所有方式进行扫描，建议基于此模式进行二次开发。
    备注：
    TCP SYN 可用于突破高端防火墙的包状态检测，TCP ACK 可用于突破防火墙的SYN包拦截， UDP 用于突破TCP协议拦截
    TCP SYN 覆盖的端口 : 25, 80, 443, 1080, 3306, 6379, 9999, 10000
    TCP ACK 覆盖的端口 : 25, 80, 443, 1080, 3306, 6379, 9999, 10000
    UDP Ping 覆盖的端口 : 34567, 45678, 56789
    SCTP INIT Ping 覆盖的端口 : 22, 80, 139, 443
    ICMP 覆盖的请求 : ICMP echo, ICMP timestamp and ICMP address
    IP 协议覆盖的协议号 : ICMP(protocol 1), IGMP(protocol 2), IP-in-IP(protocol 4), TCP(protocol 6), UDP(protocol 17), SCTP(protocol 132)
    ```
    await nmap.traceroute("lev.zone", False, False, False, True, False)
    ```
    """
    @remote
    def entry(ip):
        import subprocess
        import sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        import xmltodict
        command = ['/home/nmap/nmap', '-sn']
        if by_tcp_syn:
            command.append('-PS25,80,443,1080,3306,6379,9999,10000')
        if by_tcp_ack:
            command.append('-PA25,80,443,1080,3306,6379,9999,10000')
        if by_udp:
            command.append('-PU34567,45678,56789')
        if by_sctp:
            command.append('-PY22,80,139,443')
        if by_icmp:
            command.append('-PE')
            command.append('-PP')
            command.append('-PM')
        if by_ip:
            command.append('-PO1,2,4,6,17,132')
        command.append('-T4')
        command.append('-n')
        command.append('--traceroute')
        command.append('-oX')
        command.append('/tmp/traceroute.xml')
        command.append(ip)
        subprocess.run(command)
        res = {
            'res' : ''
        }
        try:
            with open('/tmp/traceroute.xml', 'r') as f:
                res['res'] = xmltodict.parse(f.read())
        except Exception:
            pass
        # save data into mongo
        # print(res)
        ctx.update(res)
    return Cr(".whtcjdtc2008.nmap:v1.5", entry=entry(ip))
@annot.meta(desc="nmap SYN 扫描主机开放端口、服务、主机名及操作系统",
            params=[
                annot.Param("port", "扫描的port", holder="-"),
                annot.Param("ip", "扫描的ip或ip段", holder="192.168.1.1/24"),
                annot.Param("speed", "扫描速率(1-5,越大越快)", holder="4")
            ])
def port_service_os(port:str, ip:str, speed:int = 4) -> Cr:
    """
    nmap SYN 扫描目标主机开放端口、服务、主机名及操作系统
    ```
    await nmap.port_service_os("-", "192.168.1.1/24", 5)
    await nmap.port_service_os("22,80,443", "192.168.1.1/24", 5)
    ```
    """
    @remote
    def entry(ip):
        import subprocess
        import sys
        sys.path.append("/usr/local/lib/python3.10/site-packages")
        import xmltodict
        port_param = '-p' + port
        speed_param = '-T' + str(speed)
        subprocess.run(['/home/nmap/nmap','-sS','-Pn',port_param,speed_param,'--open','-sV','-O','-oX','/tmp/port_os.xml', ip])
        res = {
            'res' : ''
        }
        try:
            with open('/tmp/port_os.xml', 'r') as f:
                res['res'] = xmltodict.parse(f.read())
        except Exception:
            pass
        ctx.update(res)
    return Cr(".whtcjdtc2008.nmap:v1.5", entry=entry(ip))
__lev__ = annot.meta([raw, typical, alive, traceroute, port_service_os],
                     desc="nmap",
                     cats={
                         Attck: [Attck.Reconnaissance],
                         BlackArch: [BlackArch.Scanner]
                     })