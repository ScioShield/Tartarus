from sigma.pipelines.elasticsearch.windows import ecs_windows
import sigma.collection
from sigma.backends.elasticsearch import LuceneBackend
import requests
from dotenv import load_dotenv
import os
import json

def SetupAPICredentials():
    load_dotenv()
    es_username = os.getenv("E_USER")
    es_password = os.getenv("E_PASS")
    CA_CERTS_PATH = os.getenv("E_CA_PATH")
    return es_username, es_password, CA_CERTS_PATH


def main():
    es_url = "https://atomicfirefly-elastic:5443/api/alerting/rule/"
    headers = {"Content-Type": "application/json", "kbn-xsrf": "true", "Connection": "keep-alive", "Accept": "application/json", "Cache-Control": "no-cache"}
    es_username, es_password, CA_CERTS_PATH = SetupAPICredentials()
    print(es_url, es_username, es_password, CA_CERTS_PATH)
    
    pipeline = ecs_windows()
    backend = LuceneBackend(pipeline)
    rules = sigma.collection.SigmaCollection.load_ruleset(inputs=["./rules/"])
    
    for i in rules:
        print(es_url + str(i.id))
        data = backend.convert_rule(i, "siem_rule")
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            data = data[0]
        print(json.dumps(data))
        response = requests.post(es_url + str(i.id), auth=(es_username, es_password), headers=headers, data=json.dumps(data), verify=CA_CERTS_PATH)
        print(response.text)
    
    print("Result: " + "\n".join(str(item) for item in backend.convert(rules, "siem_rule")))

if __name__ == "__main__":
    main()