from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import math
import os

app = FastAPI()
templates = Jinja2Templates(directory="templates")

class PricingEngine:
    def __init__(self):
        self.base_prices = {"premium": 100, "standard": 50, "economy": 20}
    
    def vulnerable_calculate(self, product_type: str, discount_logic: str, quantity: int):
        try:
            base_price = self.base_prices.get(product_type, 0)
            # Vulnerable code injection in discount calculation
            discount = eval(discount_logic, {'math': math, 'quantity': quantity})  # Injection point
            return base_price * quantity * (1 - discount)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def calculator_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})

@app.post("/calculate")
async def calculate_price(
    product_type: str = Form(...),
    discount_logic: str = Form(...),
    quantity: int = Form(...)
):
    engine = PricingEngine()
    try:
        total = engine.vulnerable_calculate(product_type, discount_logic, quantity)
        return {"product": product_type, "total_price": total}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Calculation error")

if __name__ == "__main__":
    import uvicorn
    os.makedirs("templates", exist_ok=True)
    with open("templates/form.html", "w") as f:
        f.write('''
        <!DOCTYPE html>
        <html>
        <head><title>Dynamic Pricing Calculator</title></head>
        <body>
            <h1>Product Pricing Calculator</h1>
            <form method="post" action="/calculate">
                Product Type: 
                <select name="product_type">
                    <option value="premium">Premium</option>
                    <option value="standard">Standard</option>
                    <option value="economy">Economy</option>
                </select><br>
                Quantity: <input type="number" name="quantity" min="1" value="1"><br>
                Discount Logic (Python): 
                <input type="text" name="discount_logic" 
                       placeholder="e.g., math.log(quantity)*0.1" size="40"><br>
                <button type="submit">Calculate</button>
            </form>
        </body>
        </html>
        ''')
    uvicorn.run(app, host="0.0.0.0", port=8000)