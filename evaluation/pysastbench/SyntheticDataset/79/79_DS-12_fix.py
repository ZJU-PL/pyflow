from django.http import HttpResponse
from django.shortcuts import render
from django.views import View
from django.conf import settings
from django.urls import path
from django.core.wsgi import get_wsgi_application
from django.utils.html import escape  # Import escape function
import os
import secrets  # For generating secure secret key

# Generate a secure secret key
secret_key = secrets.token_urlsafe(50)

settings.configure(
    DEBUG=False,  # Disabled debug mode
    SECRET_KEY=secret_key,  # Use generated secret key
    ROOT_URLCONF=__name__,
    TEMPLATES=[{
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
    }]
)

class Product:
    def __init__(self, id, name, price):
        self.id = id
        self.name = name
        self.price = price

PRODUCTS = [
    Product(1, "Laptop", 999.99),
    Product(2, "Phone", 699.99),
    Product(3, "Tablet", 399.99),
]

class HomeView(View):
    def get(self, request):
        return HttpResponse('''
            <h1>Welcome to Our Store</h1>
            <form action="/search" method="GET">
                <input type="text" name="query" placeholder="Search products...">
                <button type="submit">Search</button>
            </form>
            <a href="/products">View All Products</a>
        ''')

class ProductListView(View):
    def get(self, request):
        products_html = ''.join(
            f'<li>{escape(p.name)} - ${escape(str(p.price))} <a href="/product/{p.id}">View</a></li>'
            for p in PRODUCTS
        )
        return HttpResponse(f'''
            <h1>Our Products</h1>
            <ul>{products_html}</ul>
            <a href="/">Back to Home</a>
        ''')

class ProductDetailView(View):
    def get(self, request, product_id):
        product = next((p for p in PRODUCTS if p.id == product_id), None)
        if not product:
            return HttpResponse("Product not found", status=404)
        return HttpResponse(f'''
            <h1>{escape(product.name)}</h1>
            <p>Price: ${escape(str(product.price))}</p>
            <a href="/products">Back to Products</a>
        ''')

class SearchView(View):
    def get(self, request):
        query = escape(request.GET.get('query', ''))  # Escape user input
        results = [p for p in PRODUCTS if query.lower() in p.name.lower()]
        
        if not results:
            return HttpResponse(f'''
                <h1>Search Results</h1>
                <p>No products found for "<span style="color:red">{query}</span>"</p>
                <a href="/products">View All Products</a>
            ''')
        
        results_html = ''.join(
            f'<li>{escape(p.name)} - ${escape(str(p.price))}</li>' for p in results
        )
        return HttpResponse(f'''
            <h1>Search Results</h1>
            <p>Results for "<span style="color:red">{query}</span>":</p>
            <ul>{results_html}</ul>
            <a href="/products">Back to Products</a>
        ''')

urlpatterns = [
    path('', HomeView.as_view()),
    path('products/', ProductListView.as_view()),
    path('product/<int:product_id>/', ProductDetailView.as_view()),
    path('search/', SearchView.as_view()),
]

app = get_wsgi_application()

if __name__ == '__main__':
    from django.core.management import execute_from_command_line
    execute_from_command_line(['manage.py', 'runserver'])