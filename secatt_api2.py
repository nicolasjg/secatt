#!flask/bin/python
import os
import cgi
import codecs
from flask import Flask, jsonify, make_response, request, Response, render_template, url_for
from flask_compress import Compress
from whoosh import index
from whoosh.index import create_in
from whoosh.fields import Schema, STORED, TEXT
from whoosh.analysis import StemmingAnalyzer, StandardAnalyzer,NgramFilter
from whoosh.qparser import QueryParser, MultifieldParser


#security patterns references
sec_references = []
capec_url = 'https://capec.mitre.org/data/definitions/{:}.html'

#whoosh things
my_analyzer =  StemmingAnalyzer() | NgramFilter(minsize=2, maxsize=10)

sec_schema = Schema(title=TEXT(stored=True, analyzer=my_analyzer),\
    overview=TEXT(stored=True, analyzer=my_analyzer),\
    problem=TEXT(analyzer=my_analyzer),\
    id_repo=TEXT(stored=True))
    
att_schema = Schema(title=TEXT(stored=True, analyzer=my_analyzer),\
    summary=TEXT(stored=True, analyzer=my_analyzer),\
    attreq=TEXT(analyzer=my_analyzer),\
    solmit=TEXT(analyzer=my_analyzer),\
    secreq=TEXT(analyzer=my_analyzer),\
    secpri=TEXT(analyzer=my_analyzer),\
    id=TEXT(stored=True))

ix_attack = index.open_dir("index", indexname="ix_attack")
ix_security = index.open_dir("index", indexname="ix_security")

#flask things
app = Flask(__name__)
Compress(app)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/robots.txt')
def robots():
    return render_template('robots.txt')

@app.route('/api', methods=['GET'])
def search():
    query = request.args.get("search", "")

    sec_searcher = ix_security.searcher()
    qp = MultifieldParser(["title","overview","problem"], schema=ix_security.schema)
    q = qp.parse(unicode(query))
    sec_results = sec_searcher.search(q, limit=None)
    sec_list = []
    
    for sr in sec_results:
        d, dsr = {}, sr.fields()
        d['title'] = cgi.escape(dsr['title'])
        d['overview'] = cgi.escape(dsr['overview'])
        d['score'] = sr.score
        d['reference'] = cgi.escape(sec_references[ dsr['id_repo'] ])
        sec_list.append(d)

    att_searcher = ix_attack.searcher()
    qp = MultifieldParser(["title","summary","attreq","solmit","secreq","secpri"], schema=ix_attack.schema)
    q = qp.parse(unicode(query))
    att_results = att_searcher.search(q, limit=None)
    att_list = []
    
    for ar in att_results:
        d, dar = {}, ar.fields()
        d['title'] = cgi.escape(dar['title']) 
        d['overview'] = cgi.escape(dar['summary'])
        d['score'] = ar.score
        d['reference'] = cgi.escape(capec_url.format(dar['id']))
        att_list.append(d)

    resp = jsonify({'security':sec_list, 'attack':att_list})
    #TODO #FIXME #WORKARROUND 
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp
    

def get_sec_references(ref_file_path):
    d = {}
    with codecs.open(ref_file_path,'r','utf-8') as file:
        lines = file.read().splitlines()
        for line in lines:
            rid,ref = line.split(',',1)
            d[rid] = ref
    return d

if __name__ == '__main__':
    sec_references = get_sec_references('references.csv')
    port = int(os.getenv('PORT', 80))
    host = os.getenv('IP', '0.0.0.0')
    app.run(debug=True, port=port, host=host)
    
sec_references = get_sec_references('references.csv')

