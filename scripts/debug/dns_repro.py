import asyncio

from src.recon.dns_enumerator import enumerate_dns_records


async def main():
    domains = {"google.com", "example.com", "github.com"}
    results = await enumerate_dns_records(domains)
    for r in results[:10]:
        print(r)


if __name__ == "__main__":
    asyncio.run(main())
