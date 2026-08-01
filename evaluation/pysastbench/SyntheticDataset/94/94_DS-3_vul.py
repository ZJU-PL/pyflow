import tornado.ioloop
import tornado.web
import os
import json

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('''
        <form action="/render" method="post">
            <h1>Template Editor</h1>
            Template Name: <input type="text" name="name"><br>
            Template Content: <br>
            <textarea name="content" rows=10 cols=50></textarea><br>
            <input type="submit" value="Render">
        </form>
        ''')

class TemplateHandler(tornado.web.RequestHandler):
    def post(self):
        template_name = self.get_body_argument("name")
        template_content = self.get_body_argument("content")
        
        def vulnerable_render(content):
            # Vulnerable code injection through direct execution
            locals_dict = {}
            globals_dict = {'__builtins__': None}
            try:
                exec(f"result = f'''{content}'''", globals_dict, locals_dict)
                return locals_dict.get('result', '')
            except Exception as e:
                return str(e)
        
        rendered = vulnerable_render(template_content)
        self.write(f'''
        <h2>Rendered Template: {template_name}</h2>
        <div style="border:1px solid #ccc; padding:10px;">
            {rendered}
        </div>
        <a href="/">Back</a>
        ''')

class ConfigHandler(tornado.web.RequestHandler):
    def get(self):
        config = {
            "debug": True,
            "version": "1.0",
            "features": ["template", "render"]
        }
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(config))

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/render", TemplateHandler),
        (r"/config", ConfigHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()