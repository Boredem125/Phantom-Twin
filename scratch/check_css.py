import httpx

r = httpx.get("http://localhost:5173/src/components/AlertCard.tsx")
print(r.text.encode("ascii", "ignore").decode()[:1500])
