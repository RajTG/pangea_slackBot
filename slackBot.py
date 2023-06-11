from jira import JIRA
import slack_sdk as slack
import os
from flask import Flask
from slackeventsapi import SlackEventAdapter
import requests
import re
import json
import string

# Note: put creds in environment variables and import later 

slack_sign_secret = "ed35a233f44f0fe033c4cb1fa51d6ded"
slack_bot_token = "xoxb-5409681623204-5407218977027-MpEqimKH3EKHPng494b27b1L"
URL_INTEL_TOKEN = "pts_xjwmhdeziipqtsow7i4cqkerznlqoqk7"
jira_token = "ATATT3xFfGF0hfVDaWzhqLuOH70vDibWSFFwb8adCjN25uiPsMSupq2wm8biDQ19KZTqvrTCRfJeAqQqdfA165fJqQJk7b27liF82S2aZp9ifTkYe3mO66edFMMz1f-HjkSLXB--SamV1Jt2JyH0MP7EugmDpCccK8T21p5_7QRKvETbXGRijNg=884887B5"


app = Flask(__name__)


#regex for matching links in messages
link_regex = re.compile('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', re.DOTALL)




slack_event_adapter = SlackEventAdapter(slack_sign_secret, '/slack/events', app)

client = slack.WebClient(token=slack_bot_token)


#function to create issue in jira project
def create_issue(message):
    print(" /n creating issue with message ", message)
    jira_connection = JIRA(
        basic_auth=('spygunner33@gmail.com', jira_token),
        server="https://rtgcdgst.atlassian.net"
    )

    issue_dict = {
        'project': {'key': 'PT'},
        'summary': 'Malicious link shared in Slack',
        'description': message,
        'issuetype': {'name': 'Task'},
    }

    new_issue = jira_connection.create_issue(fields=issue_dict)


@ slack_event_adapter.on('message')
def message(payload):
    print(payload)
    event = payload.get('event', {})
    channel_id = event.get('channel')
    user_id = event.get('user')
    text = event.get('text')
 
    if text == "hi":
        client.chat_postMessage(channel=channel_id,text="Hello")

    print("user is ",user_id)
    print(" message is ",text)

    #checking if link is malicious by using Pangea API
    links = re.findall(link_regex, text)

    for l in links:
        print(l[0])

        link = l[0]


        headers = {
            'Authorization': 'Bearer ' + URL_INTEL_TOKEN,
            'Content-Type': 'application/json',
        }

        json_data = json.dumps({
            'provider': 'crowdstrike',
            'url': link
        })

        response = requests.post('https://url-intel.aws.us.pangea.cloud/v1/reputation', headers=headers, data = json_data)
        json_resp = response.json()
        #print(response.text)

        verdict = json_resp['result']['data']['verdict']
        print(verdict)

        if verdict == "malicious":
            #creating jira issue
            alert_msg = 'Malicious link shared in channel ' + channel_id + ' by user ' + user_id

            create_issue(alert_msg)

            #posting alert in channels
            client.chat_postMessage(channel=channel_id,text="ALERT: LINK IS MALICIOUS")
            client.chat_postMessage(channel='#jira-alert',text=alert_msg)

    
        else:
            client.chat_postMessage(channel=channel_id,text="LINK IS SAFE")


if __name__ == "__main__":
    app.run(debug=True)
