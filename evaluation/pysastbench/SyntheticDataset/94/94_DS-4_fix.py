from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import math
import os
from enum import Enum

app = FastAPI()
templates = Jinja2Templates(directory="templates")

class ProductType(str, Enum):
    PREMIUM = "premium"
    STANDARD = "standard"
    ECONOMY = "economy"

class DiscountType(str, Enum):
    BULK = "bulk"
    SEASONAL = "seasonal"
    LOYALTY = "loyalty"

class PricingEngine:
    def __init__(self):
        self.base_prices = {
            ProductType.PREMIUM: 100,
            ProductType.STANDARD: 50,
            ProductType.ECONOMY: 20
        }
        self.discount_functions = {
            DiscountType.BULK: lambda q: min(0.5, q * 0.01),
            DiscountType.SEASONAL: lambda q: 0.2 if q > 10 else 0.1,
            DiscountType.LOYALTY: lambda q: math.log(q + 1) * 0.1
        }
    
    def safe_calculate(self, product_type: ProductType, discount_type: DiscountType, quantity: int):
        try:
            if quantity <= 0:
                raise ValueError("Quantity must be positive")
                
            base_price = self.base_prices.get(product_type, 0)
            discount_func = self.discount_functions.get(discount_type)
            
            if not discount_func:
                raise ValueError("Invalid discount type")
                
            discount = discount_func(quantity)
            discount = max(0, min(0.9, discount))  # Cap discount between 0-90%
            
            return base_price * quantity * (1 - discount)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def calculator_form(request: Request):
    return templates.TemplateResponse("form.html", {
        "request": request,
        "product_types": [pt.value for pt in ProductType],
        "discount_types": [dt.value for dt in DiscountType]
    })

@app.post("/calculate")
async def calculate_price(
    product_type: ProductType = Form(...),
    discount_type: DiscountType = Form(...),
    quantity: int = Form(..., gt=0)
):
    engine = PricingEngine()
    try:
        total = engine.safe_calculate(product_type, discount_type, quantity)
        return {"product": product_type.value, "total_price": round(total, 2)}
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
                    {% for pt in product_types %}
                    <option value="{{ pt }}">{{ pt|title }}</option>
                    {% endfor %}
                </select><br>
                Quantity: <input type="number" name="quantity" min="1" value="1"><br>
                Discount Type:
                <select name="discount_type">
                    {% for dt in discount_types %}
                    <option value="{{ dt }}">{{ dt|title }}</option>
                    {% endfor %}
                </select><br>
                <button type="submit">Calculate</button>
            </form>
        </body>
        </html>
        ''')
    uvicorn.run(app, host="0.0.0.0", port=8000)