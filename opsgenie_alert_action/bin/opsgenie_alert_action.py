#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import sys
import json
import splunk.entity as entity

def get_api_key_and_region(sessionKey):
    if len(sessionKey) == 0:
        print("ERROR: Did not receive a session key from splunkd. " +
              "Please enable passAuth in inputs.conf for this script.", file=sys.stderr)
        raise Exception("No session key provided. Could not get Opsgenie API Key.")

    try:
        entities = entity.getEntities(
            ['admin', 'passwords'],
            namespace='opsgenie_alert_action',
            count=-1,
            owner='nobody',
            sessionKey=sessionKey
        )
    except Exception as e:
        raise Exception(f"Could not get Opsgenie API Key and region from credentials. Error: {str(e)}")

    api_key = None
    region = None

    for i, c in entities.items():
        if c['username'] == 'password':
            api_key = c['clear_password']
        elif c['username'] == 'region':
            region = c['clear_password']

    if api_key is None or region is None:
        raise Exception("Could not find Opsgenie API Key or region in credentials.")

    return {'api_key': api_key, 'region': region}

def send_alert(payload, api_key, region):
    region = region.lower()
    if region == "eu":
        url = "https://api.eu.opsgenie.com/v2/alerts"
    elif region == "us":
        url = "https://api.opsgenie.com/v2/alerts"
    else:
        raise ValueError("Invalid region specified. Only 'us' and 'eu' are supported.")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"GenieKey {api_key}"
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    return response.json()

def parse_responders(responders_str):
    responders = []
    for responder in responders_str.split(","):
        try:
            r_type, identifier_type, identifier_value = responder.split(":")
            responders.append({
                identifier_type: identifier_value.strip(),
                "type": r_type.strip()
            })
        except ValueError:
            pass

    return responders

def main():
    payload = json.loads(sys.stdin.read())
    config = payload.get("configuration", {})

    session_key = payload.get('session_key')

    message = config.get("search_name")
    description = config.get("message")
    priority = config.get("priority")
    actions = config.get("actions", "").split(",")
    tags = config.get("tags", "").split(",")
    note = config.get("note", "")
    source = config.get("source", "")
    result_link = config.get("result_link")
    alert_link = config.get("alert_link")
    search_query = config.get("search_query")
    view_link = config.get('view_link')
    search = config.get('search')
    responders_str = config.get("responders", "")

    details = {}
    if result_link == "1":
        details["result_link"] = payload.get("results_link")
    if search_query == "1":
        details["Splunk query"] = search
    details["Alert message"] = description
    if alert_link == "1":
        details["Alert link"] = view_link

    responders = parse_responders(responders_str)

    opsgenie_payload = {
        "message": payload.get("search_name"),
        "description": str(description),
        "priority": priority,
        "actions": actions,
        "tags": tags,
        "note": note,
        "source": source,
        "details": details,
        "entity": "Splunk SIEM",
        "responders": responders
    }

    api_key = get_api_key_and_region(session_key)['api_key']
    region = get_api_key_and_region(session_key)['region']
    response = send_alert(opsgenie_payload, api_key, region)

if __name__ == "__main__":
    main()