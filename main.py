from lev.maimai import wpscan
import levrt
from lev.maimai.wpscan import wpscan

async def raw():
    doc = await wpscan.raw(["--url", "https://quail.co.jp/"])
    data = await doc.get()
    print(data)

async def enumVulByPlugin():
    doc = await wpscan.enumVulByPlugin(["--url", "https://quail.co.jp/"])
    data = await doc.get()
    print(data)

async def enumVulByThemes():
    doc = await wpscan.enumVulByThemes(["--url", "https://quail.co.jp/"])
    data = await doc.get()
    print(data)

async def passwordBrute():
    doc = await wpscan.passwordBrute(["--url", "https://quail.co.jp/"])
    data = await doc.get()
    print(data)

if __name__ == "__main__":
    levrt.run(passwordBrute())
