# -*- coding: utf-8 -*-
"""
    Notify Google
    ------------

    Receives event payloads that are parsed and sent to Google

"""

import base64
import json
import logging
import os
import re
import urllib.parse
import urllib.request
from enum import Enum
from typing import Any, Dict, Optional, Union, cast
from urllib.error import HTTPError

import boto3

# Set default region if not provided
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Create client so its cached/frozen between invocations
KMS_CLIENT = boto3.client("kms", region_name=REGION)


class AwsService(Enum):
    """AWS service supported by function"""

    cloudwatch = "cloudwatch"
    guardduty = "guardduty"


def decrypt_url(encrypted_url: str) -> str:
    """Decrypt encrypted URL with KMS

    :param encrypted_url: URL to decrypt with KMS
    :returns: plaintext URL
    """
    try:
        decrypted_payload = KMS_CLIENT.decrypt(
            CiphertextBlob=base64.b64decode(encrypted_url)
        )
        return decrypted_payload["Plaintext"].decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")
        return ""


def get_service_url(region: str, service: str) -> str:
    """Get the appropriate service URL for the region

    :param region: name of the AWS region
    :param service: name of the AWS service
    :returns: AWS console url formatted for the region and service provided
    """
    try:
        service_name = AwsService[service].value
        if region.startswith("us-gov-"):
            return f"https://console.amazonaws-us-gov.com/{service_name}/home?region={region}"
        else:
            return f"https://console.aws.amazon.com/{service_name}/home?region={region}"

    except KeyError:
        print(f"Service {service} is currently not supported")
        raise


class CloudWatchAlarmState(Enum):
    """Maps CloudWatch notification state to Google message format color"""

    OK = "good"
    INSUFFICIENT_DATA = "warning"
    ALARM = "danger"


def format_cloudwatch_alarm(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Format CloudWatch alarm event into Google message format

    :params message: SNS message body containing CloudWatch alarm event
    :region: AWS region where the event originated from
    :returns: formatted Google message payload
    """

    cloudwatch_url = get_service_url(region=region, service="cloudwatch")
    alarm_name = message["AlarmName"]

    return {
        "cards": [
            {
                "header": {
                    "title": "AWS CloudWatch",
                    "subtitle": f"`{alarm_name}`",
                    "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/materialsymbolsoutlined/robot_2/default/24px.svg",
                    "imageStyle": "IMAGE"
                },
                "sections": [
                    {
                        "header": "Details",
                        "widgets": [
                            {
                                "textParagraph": {
                                    "text": f"<b>Alarm description:</b> `{message['NewStateReason']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Alarm reason:</b> `{message['NewStateReason']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Old State:</b> `{message['OldStateValue']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Current State:</b> `{message['NewStateValue']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Link to Alarm:</b> `{cloudwatch_url}#alarm:alarmFilter=ANY;name={urllib.parse.quote(alarm_name)}`"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


class GuardDutyFindingSeverity(Enum):
    """Maps GuardDuty finding severity to Google message format color"""

    Low = "#777777"
    Medium = "warning"
    High = "danger"


def format_guardduty_finding(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format GuardDuty finding event into Google message format

    :params message: SNS message body containing GuardDuty finding event
    :params region: AWS region where the event originated from
    :returns: formatted Google message payload
    """

    guardduty_url = get_service_url(region=region, service="guardduty")
    detail = message["detail"]
    service = detail.get("service", {})
    severity_score = detail.get("severity")

    if severity_score < 4.0:
        severity = "Low"
    elif severity_score < 7.0:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "cards": [
            {
                "header": {
                    "title": "AWS GuardDuty",
                    "subtitle": f"Finding: {detail.get('title')}",
                    "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/materialsymbolsoutlined/robot_2/default/24px.svg",
                    "imageStyle": "IMAGE"
                },
                "sections": [
                    {
                        "header": "Details",
                        "widgets": [
                            {
                                "textParagraph": {
                                    "text": f"<b>Description:</b> `{detail['description']}``"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Finding Type:</b> `{detail['type']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>First Seen:</b> `{service['eventFirstSeen']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Last Seen:</b> `{service['eventLastSeen']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Severity:</b> `{severity}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Account ID:</b> `{detail['accountId']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Count:</b> `{service['count']}`"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Link to Finding:</b> `{guardduty_url}#/findings?search=id%3D{detail['id']}`"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


class AwsHealthCategory(Enum):
    """Maps AWS Health eventTypeCategory to Google message format color

    eventTypeCategory
        The category code of the event. The possible values are issue,
        accountNotification, and scheduledChange.
    """

    accountNotification = "#777777"
    scheduledChange = "warning"
    issue = "danger"


def format_aws_health(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format AWS Health event into Google message format

    :params message: SNS message body containing AWS Health event
    :params region: AWS region where the event originated from
    :returns: formatted Google message payload
    """

    aws_health_url = (
        f"https://phd.aws.amazon.com/phd/home?region={region}#/dashboard/open-issues"
    )
    detail = message["detail"]
    resources = message.get("resources", "<unknown>")
    service = detail.get("service", "<unknown>")

    return {
        "cards": [
            {
                "header": {
                    "title": "AWS Health",
                    "subtitle": "New AWS Health Event for {service}",
                    "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/materialsymbolsoutlined/robot_2/default/24px.svg",
                    "imageStyle": "IMAGE"
                },
                "sections": [
                    {
                        "header": "Details",
                        "widgets": [
                            {
                                "textParagraph": {
                                    "text": f"<b>Affected Region:</b> {message.get('region')}"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Code:</b> {detail.get('eventTypeCode')}"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Event Description:</b> {detail['eventDescription'][0]['latestDescription']}"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Affected Resources:</b> {', '.join(resources)}"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Start Time:</b> {detail.get('startTime', '<unknown>')}"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>End Time:</b> {detail.get('endTime', '<unknown>')}"
                                }
                            },
                            {
                                "textParagraph": {
                                    "text": f"<b>Link to Event:</b> {aws_health_url}"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }   



def format_aws_backup(message: str) -> Dict[str, Any]:
    """
    Format AWS Backup event into Google message format

    :params message: SNS message body containing AWS Backup event
    :returns: formatted Google message payload
    """

    title = message.split(".")[0]

    if "failed" in title:
        title = f"⚠️ {title}"

    if "completed" in title:
        title = f"✅ {title}"

    return {
        "cards": [
            {
                "header": {
                    "title": "AWS Backup",
                    "subtitle": title,
                    "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/materialsymbolsoutlined/robot_2/default/24px.svg",
                    "imageStyle": "IMAGE"
                },
                "sections": [
                    {
                        "header": "Details",
                        "widgets": [
                            {
                                "textParagraph": {
                                    "text": message
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }   


def format_default(
    message: Union[str, Dict], subject: Optional[str] = None
) -> Dict[str, Any]:
    """
    Default formatter, converting event into Google message format

    :params message: SNS message body containing message/event
    :returns: formatted Google message payload
    """

    widgets = []

    if type(message) is dict:
        for k, v in message.items():
            value = f"{json.dumps(v)}" if isinstance(v, (dict, list)) else str(v)
            widgets.append(
                {
                    "textParagraph": {
                        "text": f"<b>{k}:</b> {v}"
                    }
                }
            )
    else:
        widgets.append(
            {
                "textParagraph": {
                    "text": message
                }
            }
        )

    return {
        "cards": [
            {
                "header": {
                    "title": "AWS notification",
                    "subtitle": "A new message",
                    "imageUrl": "https://fonts.gstatic.com/s/i/short-term/release/materialsymbolsoutlined/robot_2/default/24px.svg",
                    "imageStyle": "IMAGE"
                },
                "sections": [
                    {
                        "header": "Details",
                        "widgets": [widgets]
                    }
                ]
            }
        ]
    }   


def get_google_message_payload(
    message: Union[str, Dict], region: str, subject: Optional[str] = None
) -> Dict:
    """
    Parse notification message and format into Google message payload

    :params message: SNS message body notification payload
    :params region: AWS region where the event originated from
    :params subject: Optional subject line for Google notification
    :returns: Google message payload
    """

    payload = {}
    
    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError:
            logging.info("Not a structured payload, just a string message")

    message = cast(Dict[str, Any], message)

    if "AlarmName" in message:
        payload = format_cloudwatch_alarm(message=message, region=region)

    elif (
        isinstance(message, Dict) and message.get("detail-type") == "GuardDuty Finding"
    ):
        payload = format_guardduty_finding(
            message=message, region=message["region"]
        )

    elif isinstance(message, Dict) and message.get("detail-type") == "AWS Health Event":
        payload = format_aws_health(message=message, region=message["region"])

    elif subject == "Notification from AWS Backup":
        payload = format_aws_backup(message=str(message))

    else:
        payload = format_default(message=message, subject=subject)

    return payload


def send_google_notification(payload: Dict[str, Any]) -> str:
    """
    Send notification payload to Google

    :params payload: formatted Google message payload
    :returns: response details from sending notification
    """

    google_url = os.environ["GOOGLE_WEBHOOK_URL"]
    if not google_url.startswith("http"):
        google_url = decrypt_url(google_url)

    data = json.dumps(payload).encode("utf-8")

    headers = {"Content-Type": "application/json"}

    try:
        request = urllib.request.Request(google_url, data=data, headers=headers, method='POST')
        with urllib.request.urlopen(request) as response:
            response_data = response.read().decode('utf-8')
            data = json.loads(response_data)

        return json.dumps({
            "code": 200,
            "info": json.dumps(data)
        })
    
    except HTTPError as e:
        logging.error(f"{e}: result")
        return json.dumps({"code": e.getcode(), "info": e.info().as_string()})


def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Lambda function to parse notification events and forward to Google

    :param event: lambda expected event object
    :param context: lambda expected context object
    :returns: none
    """
    if os.environ.get("LOG_EVENTS", "False") == "True":
        logging.info(f"Event logging enabled: `{json.dumps(event)}`")

    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns["Subject"]
        message = sns["Message"]
        region = sns["TopicArn"].split(":")[3]

        payload = get_google_message_payload(
            message=message, region=region, subject=subject
        )
        response = send_google_notification(payload=payload)

    if json.loads(response)["code"] != 200:
        response_info = json.loads(response)["info"]
        logging.error(
            f"Error: received status `{response_info}` using event `{event}` and context `{context}`"
        )

    return response
