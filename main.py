from fastapi import FastAPI
from securin_cve.routes.article_routes import router as article_router

app = FastAPI()
app.include_router(article_router)
