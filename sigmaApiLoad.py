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
    es_url = "https://tartarus-elastic.home.arpa:5443/api/alerting/rule/"
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Connection": "keep-alive",
        "Accept": "application/json",
        "Cache-Control": "no-cache"
    }
    es_username, es_password, CA_CERTS_PATH = SetupAPICredentials()
 
    pipeline = ecs_windows()
    backend = LuceneBackend(pipeline)
    rules = sigma.collection.SigmaCollection.load_ruleset(inputs=["./rules/"])

    for rule in rules:
        rule_url = f"{es_url}{rule.id}"
        data = backend.convert_rule(rule, "siem_rule")
        data = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else data

        # Fetch the current rule from the remote server
        response = requests.get(rule_url, auth=(es_username, es_password), headers=headers, verify=CA_CERTS_PATH)
        remote_data = response.json() 
        
        # Get the shared keys
        shared_keys = set(data.keys()) & set(remote_data.keys())

        # Create new dictionaries that only contain the shared keys
        local_shared = {key: data[key] for key in shared_keys}
        remote_shared = {key: remote_data[key] for key in shared_keys}

        # Compare the local rule with the remote one using the shared keys
        if local_shared != remote_shared:
            # If they are different, update the remote rule
            response = requests.post(rule_url, auth=(es_username, es_password), headers=headers, data=json.dumps(data), verify=CA_CERTS_PATH)
            if response.status_code == 409:  # Conflict error
                print("Conflict error, attempting to update rule...")
                for key in ['consumer', 'enabled', 'rule_type', 'rule_type_id']:
                    data.pop(key, None)
                response = requests.put(rule_url, auth=(es_username, es_password), headers=headers, data=json.dumps(data), verify=CA_CERTS_PATH)
                print(response.text)
        else:
            response = requests.post(rule_url, auth=(es_username, es_password), headers=headers, data=json.dumps(data), verify=CA_CERTS_PATH)

    print("Result: " + "\n".join(str(item) for item in backend.convert(rules, "siem_rule")))

if __name__ == "__main__":
    main()