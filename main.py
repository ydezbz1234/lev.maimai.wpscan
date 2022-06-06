import levrt
from lev.maimai.wpscan import hello

async def main():
    doc = await hello()
    data = await doc.get()
    print(data["msg"])


if __name__ == "__main__":
    levrt.run(main())
