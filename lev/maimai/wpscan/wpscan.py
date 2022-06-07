"""
WPScan工具是一款免费的、用于非商业用途的黑盒WordPress安全扫描器，专为安全专业人员和博客维护者编写，用于测试其网站的安全性。
WPScan工具中包含28794个WordPress漏洞的数据库。
Homepage: https://wpscan.com/
GitHub: https://github.com/wpscanteam/wpscan
Type: API-BASED
Version: v3.8.22
"""
# 导入工具依赖包，分别用于启动工具镜像、将结果数据写入数据库、改写 ENTRYPOINT 和解析注释
from sys import stdout
from levrt import Cr, ctx, remote, annot
from levrt.annot.cats import Attck, BlackArch


@annot.meta(
    desc="wpscan 原生调用", params=[annot.ARGV]
    )
def raw(argv:list[str]) -> Cr:
    """
    wpscan 原生调用
    ```
    await wpscan.raw(["--url", "https://www.example.com"])
    ```
    """
    @remote
    def entry(argv):
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", *argv, "-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
       
    return Cr("talentsec/lev.maimai.wpscan:v1.0", entry=entry(argv))


@annot.meta(desc="wpscan 枚举包含有已知漏洞的插件", params=[
    annot.Param("url", "进行检测的URL", holder="https://www.example.com"),
    annot.Param("token", "wpscan.com官网申请的api-token", holder=""),
])
def enum_plugin(url:str, token:str="") -> Cr:
    """
    wpscan 使用参数-e ap 枚举所有已知漏洞的插件,检测模式为混合模式  token 为https://wpscan.com/注册的api-token
    ```
    await wpscan.enum_plugin("https://www.example.com", "str")
    ```
    """
    @remote
    def entry(url, token):
        import subprocess
        command = ["/usr/local/bin/wpscan", "-e", "ap", "--plugins-detection", "mixed",  "-f", "json", "--url", url]
        if token:
            command.append("--api-token")
            command.append(token)
        p = subprocess.Popen(command, text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
    return Cr("talentsec/lev.maimai.wpscan:v1.0", entry=entry(url, token))


@annot.meta(desc="wpscan 枚举包含有已知漏洞的主题", params=[
    annot.Param("url", "进行检测的URL", holder="https://www.example.com"),
    annot.Param("token", "wpscan.com官网申请的api-token", holder=""),
])
def enum_themes(url:str, token:str="") -> Cr:
    """
    wpscan 使用参数-e ap 枚举所有已知漏洞的主题,检测模式为混合模式 token 为https://wpscan.com/注册的api-token
    ```
    await wpscan.enum_themes("https://www.example.com", "str")
    ```
    """
    @remote
    def entry(url, token):
        import subprocess
        command = ["/usr/local/bin/wpscan", "-e", "at", "--plugins-detection", "mixed",  "-f", "json", "--url", url]
        if token:
            command.append("--api-token")
            command.append(token)
        print(command)
        p = subprocess.Popen(command, text=True, stdout=subprocess.PIPE)
        
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
    return Cr("talentsec/lev.maimai.wpscan:v1.0", entry=entry(url, token))


@annot.meta(desc="wpscan 密码爆破", params=[
    annot.Param("url", "进行检测的URL", holder="https://www.example.com"),
])
def password_brute(url:str) -> Cr:
    """
    wpscan 使用参数--passwords 暴力破解wordpress密码
    ```
    await wpscan.password_brute("https://www.example.com")
    ```
    """
    @remote
    def entry(url):
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", "--url", url, "-e", "u", "--passwords", "/usr/keyword.txt",  "-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
    return Cr("talentsec/lev.maimai.wpscan:v1.0", entry=entry(url))

@annot.meta(desc="wpscan 用户名枚举", params=[
    annot.Param("url", "进行检测的URL", holder="https://www.example.com"),
])
def username_brute(url:str) -> Cr:
    """
    wpscan 使用参数--enumerate u 枚举目标用户名
    ```
    await wpscan.username_brute("https://www.example.com")
    ```
    """
    @remote
    def entry(url):
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", "--url", url, "--enumerate", "u" ,"-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
    return Cr("talentsec/lev.maimai.wpscan:v1.0", entry=entry(url))

__lev__ = annot.meta([raw, enum_plugin, enum_themes, password_brute, username_brute],
                     desc="wpscan",
                     cats={
                         Attck: [Attck.Reconnaissance],
                         BlackArch: [BlackArch.Scanner, BlackArch.Cracker]
                     })