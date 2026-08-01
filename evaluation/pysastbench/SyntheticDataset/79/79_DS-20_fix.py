import falcon
import html
from wsgiref import simple_server

class ProductResource:
    products = [
        {'id': 1, 'name': 'Laptop', 'price': 999.99},
        {'id': 2, 'name': 'Smartphone', 'price': 699.99},
        {'id': 3, 'name': 'Tablet', 'price': 399.99},
        {'id': 4, 'name': 'Headphones', 'price': 149.99},
        {'id': 5, 'name': 'Monitor', 'price': 249.99}
    ]

    def on_get(self, req, resp):
        resp.content_type = 'text/html'
        # Escape all product data
        products_html = ''.join(
            f'<li>{html.escape(p["name"])} - ${html.escape(str(p["price"]))} '
            f'<a href="/products/{html.escape(str(p["id"]))}">View</a></li>'
            for p in self.products
        )
        resp.text = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Product Catalog</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                    .search-box {{ margin: 20px 0; }}
                </style>
            </head>
            <body>
                <h1>Product Catalog</h1>
                <div class="search-box">
                    <form action="/search" method="GET">
                        <input type="text" name="query" placeholder="Search products..." required>
                        <button type="submit">Search</button>
                    </form>
                </div>
                <ul>{products_html}</ul>
            </body>
            </html>
        '''

class ProductDetailResource:
    def on_get(self, req, resp, product_id):
        try:
            product_id = int(product_id)
        except ValueError:
            raise falcon.HTTPBadRequest('Invalid product ID')
            
        product = next((p for p in ProductResource.products if p['id'] == product_id), None)
        if not product:
            raise falcon.HTTPNotFound()
        
        resp.content_type = 'text/html'
        # Escape all product data
        resp.text = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>{html.escape(product['name'])}</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body>
                <h1>{html.escape(product['name'])}</h1>
                <p>Price: ${html.escape(str(product['price']))}</p>
                <a href="/products">Back to catalog</a>
            </body>
            </html>
        '''

class SearchResource:
    def on_get(self, req, resp):
        query = req.get_param('query', default='')
        # Escape the search query before use
        safe_query = html.escape(query)
        results = [p for p in ProductResource.products if query.lower() in p['name'].lower()]
        
        if not results:
            resp.content_type = 'text/html'
            resp.text = f'''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Search Results</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                </head>
                <body>
                    <h1>Search Results</h1>
                    <p>No products found for "{safe_query}"</p>
                    <a href="/products">Back to catalog</a>
                </body>
                </html>
            '''
            return
        
        # Escape all result data
        results_html = ''.join(
            f'<li>{html.escape(p["name"])} - ${html.escape(str(p["price"]))}</li>' 
            for p in results
        )
        resp.content_type = 'text/html'
        resp.text = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Search Results</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body>
                <h1>Search Results</h1>
                <p>Results for "{safe_query}":</p>
                <ul>{results_html}</ul>
                <a href="/products">Back to catalog</a>
            </body>
            </html>
        '''

class SecurityHeadersMiddleware:
    def process_response(self, req, resp, resource, req_succeeded):
        resp.set_header('X-Content-Type-Options', 'nosniff')
        resp.set_header('X-Frame-Options', 'DENY')
        resp.set_header('X-XSS-Protection', '1; mode=block')
        resp.set_header('Content-Security-Policy', "default-src 'self'")

app = falcon.App(middleware=[SecurityHeadersMiddleware()])
app.add_route('/products', ProductResource())
app.add_route('/products/{product_id}', ProductDetailResource())
app.add_route('/search', SearchResource())

if __name__ == '__main__':
    httpd = simple_server.make_server('127.0.0.1', 8000, app)
    print("Server started at http://127.0.0.1:8000")
    httpd.serve_forever()