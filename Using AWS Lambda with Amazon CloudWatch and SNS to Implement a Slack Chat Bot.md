- Lambda 블루프린트를 사용하여 Slack용 챗봇을 구축합니다. 챗봇은 팀 및 사용자와 상호 작용하고, 명령에 응답하고, 알림을 게시하며 모든 대화 참가자에게 팀 활동에 대한 가시성을 제공합니다. CloudWatch 경보를 수신하면 Slack 채널에 게시하는 봇을 구축합니다

- Lambda 블루프린트를 사용하여 Slack 챗봇 생성
- Slack 웹훅으로 봇을 구성하여 Slack 채널에 메시지 게시

과제 1: Slack 계정 생성

과제 2: Slack에 대해 수신 웹훅 구성
1. Apps 에 Incoming Hooks 입력
2. slack의 특정 채널에 추가
3. webhook url을 복사해둠

과제 3: SNS 주제 생성 및 구독
- SNS 주제를 생성하고 이메일 주소를 사용하여 주제를 구독한다.
- Amazon Simple Notification Service(SNS)는 구독 중인 엔드포인트 및 클라이언트에 대한 메시지 전달을 조정하는 유연한 완전관리형 게시/구독 메시징 및 모바일 알림 서비스 
- SNS를 사용하면 분산 시스템 및 서비스와 모바일 디바이스를 비롯한 많은 구독자에게 메시지를 팬아웃할 수 있습니다. 
- 이 서비스는 쉽게 설정하고 작동할 수 있으며 규모에 상관없이 모든 엔드포인트로 알림을 안정적으로 보냅니다. 
- AWS 관리 콘솔, AWS Command Line Interface를 사용하거나 간단한 세 가지 API로 AWS SDK를 사용하여 몇 분 안에 SNS 사용을 시작할 수 있습니다.
- SNS는 전용 메시징 소프트웨어 및 인프라의 관리 및 운영과 관련된 복잡성과 오버헤드를 제거합니다.

1. Slacknews 라는 이름으로 주제 생성

![](https://velog.velcdn.com/images/eunz_juu/post/a197d813-ffac-44cb-803e-0d7669e891b9/image.png)


2. Email 프로토콜을 사용하여 엔드포인트를 이메일 주소로 하여 구독 생성
→ SNS 주제가 생성되고 구독된 것!

![](https://velog.velcdn.com/images/eunz_juu/post/b0c072ca-04aa-4bef-a705-0cf726be8d27/image.png)


과제 4: Lambda 함수 생성
- Lambda : 코드만 업로드하면, 높은 가용성으로 코드 실행하고 확장하는데 필요한 모든 것을 Lambda가 처리. 또한 다른 AWS 서비스에서 자동으로 트리거하거나, 웹/모바일 앱에서 직접 호출하도록 코드 설정하는 것 또한 가능
- SNS 주제에 따라 Slack에 알림을 게시하는 블루프린트에서 Lambda 함수 생성
	- 블루프린트 : 최소한의 처리를 수행하는 이벤트 소스 및 Lambda 함수의 샘플 구성으로, 필요에 따라 사용자 지정
    	- 새 AWS Lambda 함수를 생성할 때 시나리오에 가장 적합한 블루프린트를 사용할 수 있습니다. Slack slash 명령을 처리하고 세부 정보를 사용자에게 다시 에코하는 함수와 CloudWatch 경보 알림을 Slack으로 보내는 Amazon SNS 트리거를 포함하여 여러 가지 Slack 봇 블루프린트를 사용할 수 있습니다.
- cloudwatch-alarm-to-slack-python 를 검색하여 Slackfunction 이라는 이름으로 함수 생성 
- SNS topic 은 slacknews
- 환경변수에는 채널 이름과 웹훅 주소를 입력


```python
import boto3
import json
import logging
import os

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

HOOK_URL = os.environ['kmsEncryptedHookUrl']
SLACK_CHANNEL = os.environ['slackChannel']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = event['Records'][0]['Sns']['Message']
    logger.info("Message: " + str(message))

    alarm_name = message['AlarmName']
    new_state = message['NewStateValue']
    reason = message['NewStateReason']

    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': "%s state is now %s: %s" % (alarm_name, new_state, reason)
    }

    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)

```
과제 5: Lambda 함수 테스트 
- 아래의 JSON 코드를 복사함
```JSON
{
  "Records": [
    {
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
      "EventSource": "aws:sns",
      "Sns": {
        "SignatureVersion": "1",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "Message": {
          "AlarmName": "SlackAlarm",
          "NewStateValue": "OK",
          "NewStateReason":"Threshold Crossed: 1 datapoint (0.0) was not greater than or equal to the threshold (1.0)."
        },
        "MessageAttributes": {
          "Test": {
            "Type": "String",
            "Value": "TestString"
          },
          "TestBinary": {
            "Type": "Binary",
            "Value": "TestBinary"
          }
        },
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}
```
- 따라서 Records > Message 아래의 값들로 메시지가 채워져서 슬랙 알림이 옴


과제 6: CloudWatch 경보 생성
- 경보가 트리거될 때 SNS 주제에 알리는 CloudWatch 경보 생성

`Amazon CloudWatch` : AWS에서 실행하는 AWS 클라우드 리소스와 애플리케이션에 대한 모니터링 서비스
- Amazon CloudWatch를 사용하면 지표를 수집 및 추적하거나, 로그 파일을 수집 및 모니터링하거나, 경보를 설정하거나, AWS 리소스 변경에 자동으로 대응 가능
- Amazon CloudWatch는 Amazon EC2 인스턴스, Amazon DynamoDB 테이블, Amazon RDS DB 인스턴스 같은 AWS 리소스뿐만 아니라 애플리케이션과 서비스에서 생성된 사용자 정의 지표 및 애플리케이션에서 생성된 모든 로그 파일을 모니터링 가능

Lambda 블루프린트를 사용하여 Slack 챗봇을 생성
Slack 웹훅으로 봇을 구성하고 Slack 채널에 성공적으로 메시지를 게시
챗봇을 테스트하고 CloudWatch 경보를 Slack 채널에 게시하는지 확인

- cloud watch 에서 alarm 생성

결론 : AWS lambda를 사용하여 자체 Slack 봇 생성
```
Lambda 블루프린트를 사용하여 Slack 챗봇을 생성
Slack 웹훅으로 봇을 구성하고 Slack 채널에 성공적으로 메시지를 게시
챗봇을 테스트하고 CloudWatch 경보를 Slack 채널에 게시하는지 확인
```
