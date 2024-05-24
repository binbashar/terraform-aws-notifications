# terraform-aws-notifications
Terraform module which creates SNS topic and Lambda function which sends notifications

## Usage

```hcl
module "notify_slack" {
  source  = "terraform-aws-modules/notify-slack/aws"
  version = "~> 5.0"

  sns_topic_name = "slack-topic"

  slack_webhook_url = "https://hooks.slack.com/services/AAA/BBB/CCC"
  slack_channel     = "aws-notification"
  slack_username    = "reporter"
}
```