"""
WPScan工具是一款免费的、用于非商业用途的黑盒WordPress安全扫描器，专为安全专业人员和博客维护者编写，用于测试其网站的安全性。WPScan工具中包含28794个WordPress漏洞的数据库。
Homepage: https://wpscan.com/
GitHub: https://github.com/wpscanteam/wpscan
Type: IMAGE-BASED
Version: v3.8.22
"""
# 导入工具依赖包，分别用于启动工具镜像、将结果数据写入数据库、改写 ENTRYPOINT 和解析注释
from sys import stdout
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
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", *argv, "-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
       
    return Cr("0a875cc585fa", entry=entry(argv))


@annot.meta(desc="wpscan 枚举包含有已知漏洞的插件", params=[annot.ARGV])
def enumVulByPlugin(argv:list[str]) -> Cr:
    """
    wpscan 使用参数-e ap 枚举所有已知漏洞的插件,检测模式为混合模式  --api-token 为https://wpscan.com/注册的api-token
    ```
    await wpscan.enumVulByPlugin(["--url", "https://www.example.com", "--api-token", "false"])
    ```
    """
    @remote
    def entry(argv):
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", *argv, "-e", "ap", "--plugins-detection", "mixed",  "-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
    return Cr("4a6783b38924", entry=entry(argv))


@annot.meta(desc="wpscan 枚举包含有已知漏洞的主题", params=[annot.ARGV])
def enumVulByThemes(argv:list[str]) -> Cr:
    """
    wpscan 使用参数-e ap 枚举所有已知漏洞的主题,检测模式为混合模式 --api-token 为https://wpscan.com/注册的api-token
    ```
    await wpscan.enumVulByThemes(["--url", "https://www.example.com", "--api-token", "false"])
    ```
    """
    @remote
    def entry(argv):
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", *argv, "-e", "at", "--plugins-detection", "mixed",  "-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        ctx.update(data)
    return Cr("4a6783b38924", entry=entry(argv))


@annot.meta(desc="wpscan 密码爆破", params=[annot.ARGV])
def passwordBrute(argv:list[str]) -> Cr:
    """
    wpscan 使用参数--passwords 暴力破解wordpress密码
    ```
    await wpscan.passwordBrute(["--url", "https://www.example.com")
    ```
    """
    @remote
    def entry(argv):
        import subprocess
        p = subprocess.Popen(["/usr/local/bin/wpscan", *argv, "-e", "u", "--passwords", "/usr/keyword.txt",  "-f", "json"], text=True, stdout=subprocess.PIPE)
        stdoutdata, stderrdata = p.communicate()
        data = {"result": stdoutdata}
        print(data)
        ctx.update(data)
    return Cr("4a6783b38924", entry=entry(argv))

__lev__ = annot.meta([raw],
                     desc="wpscan",
                     cats={
                         Attck: [Attck.Reconnaissance],
                         BlackArch: [BlackArch.Scanner]
                     })