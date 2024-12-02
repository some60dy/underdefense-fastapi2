from fastapi import FastAPI, Query, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from elasticsearch import Elasticsearch
import requests

# Elasticsearch configuration
ES_CLOUD_ID = "d27fb9a547234d009683fa5aaa8db8c7:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJDYzMGViOTQ5MDk0MTRhYzNiYjc4MGRmMzE3ZDE2YmM5JGRiMTM2YTA4M2FkNDRkN2VhYmZlNWE4YmEzODNkNTlm"
ES_API_KEY = "ZVJ5b2lKTUJTMndmOVhpRkpYelI6LVM2MU9kOFJUMVdEMVU0dzZEU3VHUQ=="
INDEX_NAME = "cve_data"

# Initialize Elasticsearch
es = Elasticsearch(
    cloud_id=ES_CLOUD_ID,
    api_key=ES_API_KEY,
    verify_certs=True
)

# Initialize FastAPI
app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# CVE feed URL
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@app.get("/info")
async def info(request: Request):
    return templates.TemplateResponse("info.html", {
        "request": request,
        "app_name": "CVE Viewer",
        "author": "Taras Popovych",
        "description": "UNDERDEFENSE TASK1"
    })

@app.post("/init-db")
def init_db(request: Request):
    response = requests.get(url)
    if response.status_code == 200:
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not es.indices.exists(index=INDEX_NAME):
            es.indices.create(index=INDEX_NAME)

        for vuln in vulnerabilities:
            es.index(index=INDEX_NAME, id=vuln.get("cveID"), document=vuln)
        return templates.TemplateResponse("init.html", {
            "request": request,
            "message": "Database initialized successfully."
        })
    return templates.TemplateResponse("error.html", {
        "request": request,
        "error": "Failed to fetch CVE data."
    })

@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/get/new")
def get_new_cves(request: Request):
    response = es.search(
        index=INDEX_NAME,
        body={
            "query": {"match_all": {}},
            "sort": [{"cveID.keyword": {"order": "desc"}}],
            "size": 10
        }
    )
    cves = [hit["_source"] for hit in response["hits"]["hits"]]
    return templates.TemplateResponse("cve_list.html", {"request": request, "cves": cves})

@app.get("/get/all")
def get_recent_cves(request: Request):
    response = es.search(
        index=INDEX_NAME,
        body={
            "query": {"match_all": {}},
            "size": 40
        }
    )
    cves = [hit["_source"] for hit in response["hits"]["hits"]]
    return templates.TemplateResponse("cve_list.html", {"request": request, "cves": cves})

@app.get("/get/known")
def get_known_ransomware(request: Request):
    response = es.search(
        index=INDEX_NAME,
        body={
            "query": {"term": {"knownRansomwareCampaignUse.keyword": "Known"}},
            "size": 10
        }
    )
    cves = [hit["_source"] for hit in response["hits"]["hits"]]
    return templates.TemplateResponse("cve_list.html", {"request": request, "cves": cves})

@app.get("/get")
def search(request: Request, query: str = Query(...)):
    response = es.search(
        index=INDEX_NAME,
        body={
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["cveID", "notes"]
                }
            }
        }
    )
    cves = [hit["_source"] for hit in response["hits"]["hits"]]
    return templates.TemplateResponse("cve_list.html", {"request": request, "cves": cves})
