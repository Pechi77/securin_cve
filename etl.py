"""Script to request data from https://nvd.nist.gov/developers/vulnerabilities
and writes to database
"""
import time

import requests
import pymongo


MONGODB_SERVER = "localhost"
MONGODB_PORT = 27017
MONGODB_DB = "securin"
MONGODB_COLLECTION = "cve"


connection = pymongo.MongoClient(
            MONGODB_SERVER,
            MONGODB_PORT
        )
db = connection[MONGODB_DB]
collection = db[MONGODB_COLLECTION]


db.collection.create_index([("id", pymongo.ASCENDING)], unique=True)

def insert_to_database(records):
    collection.insert_many(records, ordered=False)
    
def preprocess(cve):
    cve["id"] = cve["id"].lower()
    return cve


def get_total_results():
    HOME = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
    response = requests.get(HOME)

    data = response.json()
    total_results = data.get("totalResults")

    return total_results


def main():
    total_results = get_total_results()

    for page in range(0, total_results, 2000):
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={page+2000}"
        print(url)
        response = requests.get(url)
        vulnerabilities = response.json()['vulnerabilities']
        insert_to_database([preprocess(vulnerability.get("cve").copy()) for vulnerability in vulnerabilities])
        
        time.sleep(3)

    # total_cvs.extend([vulnerability.get("cve").copy() for vulnerability in vulnerabilities])

if __name__ == '__main__':
    main()
    