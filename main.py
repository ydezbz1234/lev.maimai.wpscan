from lev.maimai import wpscan
import levrt
from lev.maimai.wpscan import wpscan

async def raw():
    doc = await wpscan.raw(["--url", "https://www.scpronet.com/wordpress/"])
    data = await doc.get()
    print(data)

async def enum_plugin():
    doc = await wpscan.enum_plugin("https://www.scpronet.com/wordpress/")
    data = await doc.get()
    print(data)

async def enum_themes():
    doc = await wpscan.enum_themes("https://www.scpronet.com/wordpress/")
    data = await doc.get()
    print(data)

async def password_brute():
    doc = await wpscan.password_brute("https://www.scpronet.com/wordpress/")
    data = await doc.get()
    print(data)

async def username_brute():
    doc = await wpscan.username_brute("https://www.scpronet.com/wordpress/")
    data = await doc.get()
    print(data)


if __name__ == "__main__":
    levrt.run(enum_themes())
