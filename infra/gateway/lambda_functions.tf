################################################################################
# Per-Capability Lambda Functions
#
# Replaces the monolith Lambda with 8 scoped functions, each with least-privilege
# IAM policies. The old monolith in lambda.tf remains active until routes are
# switched over and verified.
################################################################################

locals {
  # ---------------------------------------------------------------------------
  # DynamoDB action sets
  # ---------------------------------------------------------------------------
  ddb_read_actions = [
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:BatchGetItem",
  ]

  ddb_write_actions = [
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:BatchGetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:BatchWriteItem",
  ]

  # ---------------------------------------------------------------------------
  # Per-function capability matrix
  # ---------------------------------------------------------------------------
  fn_capabilities = {
    saml-sso = {
      config_ddb_actions  = local.ddb_write_actions
      session_ddb_actions = local.ddb_write_actions
      kms_sign            = true
      kms_encrypt         = true
      kms_get_public_key  = true
      cognito             = true
      cw_logs_audit       = true
      sm_oidc_key         = false
      sm_edge_key         = true
    }
    saml-slo = {
      config_ddb_actions  = local.ddb_read_actions
      session_ddb_actions = local.ddb_write_actions
      kms_sign            = false
      kms_encrypt         = false
      kms_get_public_key  = false
      cognito             = false
      cw_logs_audit       = true
      sm_oidc_key         = false
      sm_edge_key         = true
    }
    saml-metadata = {
      config_ddb_actions  = local.ddb_write_actions
      session_ddb_actions = []
      kms_sign            = true
      kms_encrypt         = false
      kms_get_public_key  = true
      cognito             = false
      cw_logs_audit       = false
      sm_oidc_key         = false
      sm_edge_key         = true
    }
    oidc-authorize = {
      config_ddb_actions  = local.ddb_read_actions
      session_ddb_actions = local.ddb_write_actions
      kms_sign            = true
      kms_encrypt         = true
      kms_get_public_key  = true
      cognito             = true
      cw_logs_audit       = true
      sm_oidc_key         = true
      sm_edge_key         = true
    }
    oidc-token = {
      config_ddb_actions  = local.ddb_read_actions
      session_ddb_actions = local.ddb_write_actions
      kms_sign            = true
      kms_encrypt         = false
      kms_get_public_key  = true
      cognito             = false
      cw_logs_audit       = true
      sm_oidc_key         = true
      sm_edge_key         = true
    }
    oidc-discovery = {
      config_ddb_actions  = local.ddb_read_actions
      session_ddb_actions = []
      kms_sign            = false
      kms_encrypt         = false
      kms_get_public_key  = true
      cognito             = false
      cw_logs_audit       = false
      sm_oidc_key         = true
      sm_edge_key         = true
    }
    management-api = {
      # list-tenants scans the config table by PK prefix "TENANT#"
      # (internal/store/tenant_store.go ScanByPKPrefix), so management-api needs
      # dynamodb:Scan on the config table too — not only the session table.
      # The onboarding wizard persists its multi-step state in the session table
      # (store.NewOnboardingStateStore), so management-api needs write access there
      # in addition to the analytics read path.
      config_ddb_actions  = concat(local.ddb_write_actions, ["dynamodb:Scan"])
      session_ddb_actions = concat(local.ddb_write_actions, ["dynamodb:Scan"])
      kms_sign            = true # CSR generation signs with the KMS key; import reads the public key
      kms_encrypt         = false
      kms_get_public_key  = true
      cognito             = false
      cw_logs_audit       = true # onboarding service calls auditLogger (PutLogEvents); read access below is additive
      sm_oidc_key         = false
      sm_edge_key         = true
    }
    health = {
      config_ddb_actions  = []
      session_ddb_actions = []
      kms_sign            = false
      kms_encrypt         = false
      kms_get_public_key  = false
      cognito             = false
      cw_logs_audit       = false
      sm_oidc_key         = false
      sm_edge_key         = false # health function has no config.Load and needs no edge gate
    }
  }

  # ---------------------------------------------------------------------------
  # Per-function environment variables
  # ---------------------------------------------------------------------------
  fn_common_env = {
    PROXY_ENVIRONMENT = var.environment
    PROXY_AWS_REGION  = var.aws_region
    PROXY_LOG_LEVEL   = var.log_level
    # CloudFront origin-verify edge secret — Secrets Manager ARN. Every
    # request-handling function fetches the secret at cold-start via
    # secretsmanager:GetSecretValue and passes the value to
    # middleware.RequireEdgeSecret; the raw 48-character token is never stored in
    # the Lambda environment (it was previously exposed there as
    # PROXY_EDGE_AUTH_SECRET). config.Load requires this ARN in every deployed
    # environment; the health function has no config.Load and receives no var.
    PROXY_EDGE_AUTH_SECRET_ARN = aws_secretsmanager_secret.edge_secret.arn
    # Cognito pool + SPA app-client IDs. config.Load requires BOTH
    # in every deployed (non-local) environment — see internal/config/config.go
    # Load(): the check is universal, not management-API-specific, so every
    # function that calls config.Load fails init closed without them (an empty
    # pool ID leaves the JWKS verifier un-built; an empty client ID makes it skip
    # the aud check). They therefore belong here in the common env alongside
    # PROXY_EDGE_AUTH_SECRET_ARN, not only on management-api. Both are non-secret
    # identifiers already published as gateway outputs. (health ignores its env;
    # receiving them is harmless, exactly as with the edge secret ARN above.)
    PROXY_COGNITO_POOL_ID   = aws_cognito_user_pool.main.id
    PROXY_COGNITO_CLIENT_ID = local.cognito_spa_client_id
  }

  fn_env_vars = {
    saml-sso = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE        = module.dynamodb.dynamodb_table_id
      PROXY_SESSION_TABLE         = module.dynamodb_session.dynamodb_table_id
      PROXY_KMS_KEY_ID            = module.kms_saml_signing.key_id
      PROXY_KMS_KEY_ID_BACKUP     = local.backup_signing_key_id
      PROXY_KMS_ENCRYPTION_KEY_ID = module.kms_encryption.key_id
      PROXY_ENTITY_ID             = var.saml_entity_id
      PROXY_BASE_URL              = local.base_url
      PROXY_TENANT_MODE           = "pool"
    })
    saml-slo = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE = module.dynamodb.dynamodb_table_id
      PROXY_SESSION_TABLE  = module.dynamodb_session.dynamodb_table_id
      PROXY_ENTITY_ID      = var.saml_entity_id
      PROXY_BASE_URL       = local.base_url
      PROXY_TENANT_MODE    = "pool"
    })
    saml-metadata = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE    = module.dynamodb.dynamodb_table_id
      PROXY_KMS_KEY_ID        = module.kms_saml_signing.key_id
      PROXY_KMS_KEY_ID_BACKUP = local.backup_signing_key_id
      PROXY_ENTITY_ID         = var.saml_entity_id
      PROXY_BASE_URL          = local.base_url
      PROXY_TENANT_MODE       = "pool"
    })
    oidc-authorize = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE        = module.dynamodb.dynamodb_table_id
      PROXY_SESSION_TABLE         = module.dynamodb_session.dynamodb_table_id
      PROXY_KMS_KEY_ID            = module.kms_saml_signing.key_id
      PROXY_KMS_KEY_ID_BACKUP     = local.backup_signing_key_id
      PROXY_KMS_ENCRYPTION_KEY_ID = module.kms_encryption.key_id
      PROXY_ENTITY_ID             = var.saml_entity_id
      PROXY_BASE_URL              = local.base_url
      PROXY_ENABLE_OIDC           = "true"
      PROXY_TENANT_MODE           = "pool"
      # MF-5: shared AES-GCM key for opaque bearer token encryption.
      PROXY_OIDC_CRYPTO_KEY_SECRET_ARN = aws_secretsmanager_secret.oidc_crypto_key.arn
    })
    oidc-token = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE    = module.dynamodb.dynamodb_table_id
      PROXY_SESSION_TABLE     = module.dynamodb_session.dynamodb_table_id
      PROXY_KMS_KEY_ID        = module.kms_saml_signing.key_id
      PROXY_KMS_KEY_ID_BACKUP = local.backup_signing_key_id
      PROXY_ENTITY_ID         = var.saml_entity_id
      PROXY_BASE_URL          = local.base_url
      PROXY_ENABLE_OIDC       = "true"
      PROXY_TENANT_MODE       = "pool"
      # MF-5: shared AES-GCM key for opaque bearer token encryption.
      PROXY_OIDC_CRYPTO_KEY_SECRET_ARN = aws_secretsmanager_secret.oidc_crypto_key.arn
    })
    oidc-discovery = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE    = module.dynamodb.dynamodb_table_id
      PROXY_KMS_KEY_ID        = module.kms_saml_signing.key_id
      PROXY_KMS_KEY_ID_BACKUP = local.backup_signing_key_id
      PROXY_ENTITY_ID         = var.saml_entity_id
      PROXY_BASE_URL          = local.base_url
      PROXY_ENABLE_OIDC       = "true"
      PROXY_TENANT_MODE       = "pool"
      # MF-5: shared AES-GCM key for opaque bearer token encryption.
      PROXY_OIDC_CRYPTO_KEY_SECRET_ARN = aws_secretsmanager_secret.oidc_crypto_key.arn
    })
    management-api = merge(local.fn_common_env, {
      PROXY_DYNAMODB_TABLE       = module.dynamodb.dynamodb_table_id
      PROXY_SESSION_TABLE        = module.dynamodb_session.dynamodb_table_id
      PROXY_KMS_KEY_ID           = module.kms_saml_signing.key_id
      PROXY_KMS_KEY_ID_BACKUP    = local.backup_signing_key_id
      PROXY_ENTITY_ID            = var.saml_entity_id
      PROXY_TENANT_MODE          = "pool"
      PROXY_SAAS_ACCOUNT_ID      = data.aws_caller_identity.current.account_id
      PROXY_SAAS_PRINCIPAL_NAME  = "${local.name_prefix}-management-api"
      PROXY_IAC_TEMPLATES_BUCKET = module.iac_templates_bucket.s3_bucket_id
      # Templates are served through CloudFront/OAC from a private bucket,
      # so the download URLs handed to customers use the CloudFront base URL, not
      # the S3 virtual-hosted host. local.base_url is the CloudFront domain (or
      # custom domain); the /templates/* behavior fronts the bucket there.
      PROXY_IAC_TEMPLATES_BASE_URL = local.base_url
      # Management-API JWT auth relies on the in-process Cognito JWKS verifier
      # driven by PROXY_COGNITO_POOL_ID / PROXY_COGNITO_CLIENT_ID. Those
      # now come from fn_common_env (config.Load requires them in every deployed
      # function, not just this one), so they are no longer set here — merge would
      # only duplicate them.
    })
    health = local.fn_common_env
  }

  # ---------------------------------------------------------------------------
  # Per-function IAM policy_statements (built dynamically from capabilities)
  # ---------------------------------------------------------------------------
  fn_policy_statements = {
    for name, caps in local.fn_capabilities : name => merge(
      # Config DynamoDB
      length(caps.config_ddb_actions) > 0 ? {
        config_dynamodb = {
          effect  = "Allow"
          actions = caps.config_ddb_actions
          resources = [
            module.dynamodb.dynamodb_table_arn,
            "${module.dynamodb.dynamodb_table_arn}/index/*",
          ]
        }
      } : {},

      # Session DynamoDB
      length(caps.session_ddb_actions) > 0 ? {
        session_dynamodb = {
          effect  = "Allow"
          actions = caps.session_ddb_actions
          resources = [
            module.dynamodb_session.dynamodb_table_arn,
            "${module.dynamodb_session.dynamodb_table_arn}/index/*",
          ]
        }
      } : {},

      # KMS signing key (Sign + GetPublicKey + DescribeKey)
      caps.kms_sign ? {
        kms_signing = {
          effect = "Allow"
          actions = [
            "kms:Sign",
            "kms:GetPublicKey",
            "kms:DescribeKey",
          ]
          resources = local.signing_key_arns
        }
      } : {},

      # KMS signing key (GetPublicKey only, no Sign)
      !caps.kms_sign && caps.kms_get_public_key ? {
        kms_public_key = {
          effect = "Allow"
          actions = [
            "kms:GetPublicKey",
            "kms:DescribeKey",
          ]
          resources = local.signing_key_arns
        }
      } : {},

      # KMS encryption key — for cookie encryption (GenerateDataKey)
      caps.kms_encrypt ? {
        kms_encryption = {
          effect = "Allow"
          actions = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:DescribeKey",
          ]
          resources = [module.kms_encryption.key_arn]
        }
      } : {},

      # KMS encryption key — for DynamoDB SSE (any function reading/writing DDB needs this)
      length(caps.config_ddb_actions) > 0 || length(caps.session_ddb_actions) > 0 ? {
        kms_ddb_encryption = {
          effect = "Allow"
          actions = [
            "kms:Decrypt",
            "kms:DescribeKey",
          ]
          resources = [module.kms_encryption.key_arn]
        }
      } : {},

      # Cognito
      caps.cognito ? {
        cognito = {
          effect = "Allow"
          actions = [
            "cognito-idp:DescribeUserPool",
            "cognito-idp:DescribeUserPoolClient",
            "cognito-idp:AdminGetUser",
            "cognito-idp:AdminListGroupsForUser",
          ]
          resources = [aws_cognito_user_pool.main.arn]
        }
      } : {},

      # CloudWatch audit logs (write)
      caps.cw_logs_audit ? {
        cloudwatch_audit = {
          effect = "Allow"
          actions = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          resources = [
            aws_cloudwatch_log_group.audit.arn,
            "${aws_cloudwatch_log_group.audit.arn}:*",
          ]
        }
      } : {},

      # MF-5: Secrets Manager read for the shared OIDC CryptoKey
      caps.sm_oidc_key ? {
        sm_oidc_key = {
          effect    = "Allow"
          actions   = ["secretsmanager:GetSecretValue"]
          resources = [aws_secretsmanager_secret.oidc_crypto_key.arn]
        }
      } : {},

      # Secrets Manager read for the CloudFront origin-verify edge secret.
      # The raw 48-character token is fetched once at cold-start and passed to
      # middleware.RequireEdgeSecret; it is never stored in the Lambda env.
      caps.sm_edge_key ? {
        sm_edge_key = {
          effect    = "Allow"
          actions   = ["secretsmanager:GetSecretValue"]
          resources = [aws_secretsmanager_secret.edge_secret.arn]
        }
      } : {},

      # Management API gets CloudWatch Logs Insights read access
      name == "management-api" ? merge({
        cloudwatch_audit_read = {
          effect = "Allow"
          actions = [
            "logs:StartQuery",
            "logs:GetQueryResults",
            "logs:StopQuery",
          ]
          resources = [
            aws_cloudwatch_log_group.audit.arn,
            "${aws_cloudwatch_log_group.audit.arn}:*",
          ]
        }
        iac_templates_write = {
          effect    = "Allow"
          actions   = ["s3:PutObject"]
          resources = ["${module.iac_templates_bucket.s3_bucket_arn}/templates/*"]
        }
        },
        # Cross-account tenant-role assumption is scoped to the explicit
        # allow-list of onboarded account IDs — never an account wildcard.
        # The resources name concrete accounts, so this role can only assume
        # identity-gateway-<tenant> in accounts THIS deployment has been told to
        # trust. The per-tenant sts:ExternalId condition on the customer-owned
        # trust policy (see internal/iac/templates/cfn.yaml.tmpl) remains as
        # defense-in-depth. When the allow-list is empty the statement is omitted
        # entirely: the grant fails closed until a tenant account is added.
        length(var.tenant_account_ids) > 0 ? {
          sts_assume_tenant_role = {
            effect  = "Allow"
            actions = ["sts:AssumeRole"]
            resources = [
              for acct in var.tenant_account_ids :
              "arn:aws:iam::${acct}:role/identity-gateway-*"
            ]
          }
      } : {}) : {},
    )
  }
}

################################################################################
# Lambda Functions (one per capability)
################################################################################

module "lambda_fn" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 8.7"

  for_each = local.lambda_functions

  function_name = "${local.name_prefix}-${each.key}"
  description   = each.value.description

  package_type  = "Image"
  architectures = ["arm64"]
  # MF-12: deploy by immutable digest, never by mutable tag. The digest for
  # each capability is captured at build/push time and supplied via
  # var.image_digests (validated to sha256:<64hex>). A plain index is used on
  # purpose: when a key is absent the lookup errors at plan/apply, so a real
  # apply fails closed rather than silently falling back to a re-pointable tag.
  # var.image_tag is retained as a human-facing build reference only (see the
  # Function tag below and the image_tag output), and never feeds image_uri.
  image_uri      = "${data.terraform_remote_state.registry.outputs.ecr_repository_urls[each.key]}@${var.image_digests[each.key]}"
  create_package = false

  # MF-11: DoS / cost ceiling. Every function sits behind the same
  # internet-reachable API and the unauthenticated SAML/OIDC routes have no
  # API-Gateway authorizer, so a flood of the execute-api host would otherwise
  # force uncapped concurrent invocations before the edge-secret 403. Reserving
  # a fixed per-function ceiling bounds that blast radius (and gives each
  # function a guaranteed floor). -1 opts a deployment out (see the variable).
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  memory_size = each.value.memory
  timeout     = each.value.timeout

  environment_variables = local.fn_env_vars[each.key]

  # Use the symmetric encryption key for CloudWatch logs
  cloudwatch_logs_kms_key_id = module.kms_encryption.key_arn
  # checkov:skip=CKV_AWS_338: Lambda operational logs are short-lived debug output;
  # audit-trail durability is handled by the dedicated /identity-gateway/audit
  # log group (365-day retention) not here.
  cloudwatch_logs_retention_in_days = var.environment == "prod" ? 90 : 14

  # IAM policies — scoped per function
  attach_policy_statements = length(keys(local.fn_policy_statements[each.key])) > 0
  policy_statements        = local.fn_policy_statements[each.key]

  tags = merge({
    Component = "compute"
    Function  = each.key
    # Human-facing build reference only. The function is deployed by immutable
    # digest (image_uri above); this tag records the tag that digest was built
    # from and does NOT influence which image runs.
    ImageTag = var.image_tag
  })
}

################################################################################
# Lambda Permissions — API Gateway invoke
################################################################################

resource "aws_lambda_permission" "api_gateway_fn" {
  for_each = local.lambda_functions

  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_fn[each.key].lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
