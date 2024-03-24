from fastapi import FastAPI, HTTPException

app = FastAPI()

fake_db = {} # In-memory database

@app.get("/items/{item_id}")
async def read_item(item_id: str):
    if item_id not in fake_db:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item_id": item_id, "data": fake_db[item_id]}