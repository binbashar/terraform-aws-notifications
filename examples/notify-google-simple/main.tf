provider "aws" {
  region = local.region
}

locals {
  name   = "ex-${replace(basename(path.cwd), "_", "-")}"
  region = "us-east-1"
  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}


################################################################################
# Slack Notify Module
################################################################################

module "notify_slack" {
  source = "../../"

  #
  # Creation Flags
  #
  create           = true
  create_sns_topic = true

  chatops_app        = "google"
  google_webhook_url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=BBBB"

  lambda_function_name = local.name
  lambda_description   = "Lambda function which sends notifications to Google"
  log_events           = true
  sns_topic_name       = local.name

}
