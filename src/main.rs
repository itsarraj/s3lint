use std::process::ExitCode;

use aws_sdk_s3::config::{Credentials, Region};
use clap::Parser;
use s3lint::lint::{lint_policy, Severity};

#[derive(Parser)]
#[command(
    name = "s3lint",
    about = "Audits an S3-compatible bucket's real policy for public-access misconfigurations"
)]
struct Cli {
    #[arg(long)]
    bucket: String,
    /// S3-compatible endpoint (omit for real AWS S3).
    #[arg(long, env = "AWS_ENDPOINT")]
    endpoint: Option<String>,
    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    access_key: String,
    #[arg(long, env = "AWS_SECRET_ACCESS_KEY")]
    secret_key: String,
    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    region: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let credentials = Credentials::new(&cli.access_key, &cli.secret_key, None, None, "s3lint");
    let mut builder = aws_sdk_s3::config::Builder::new()
        .region(Region::new(cli.region.clone()))
        .credentials_provider(credentials)
        .force_path_style(true)
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest());
    if let Some(endpoint) = &cli.endpoint {
        builder = builder.endpoint_url(endpoint);
    }
    let client = aws_sdk_s3::Client::from_conf(builder.build());

    let policy_result = client.get_bucket_policy().bucket(&cli.bucket).send().await;
    let policy_json = match policy_result {
        Ok(output) => output.policy().unwrap_or("").to_string(),
        Err(e) => {
            // `e.to_string()` on an SdkError only ever says the generic
            // "service error" — found live, this meant the intended
            // "no policy set" case was never actually detected and fell
            // through to a hard failure instead. The real error code
            // lives one level deeper, in the parsed service error.
            let is_no_such_policy = e
                .as_service_error()
                .map(|se| se.meta().code() == Some("NoSuchBucketPolicy"))
                .unwrap_or(false);
            if is_no_such_policy {
                println!(
                    "s3lint: no bucket policy set on '{}' (access is governed by IAM/ACL only)",
                    cli.bucket
                );
                return ExitCode::SUCCESS;
            }
            eprintln!("s3lint: fetching bucket policy: {e}");
            return ExitCode::FAILURE;
        }
    };

    let findings = match lint_policy(&policy_json) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("s3lint: parsing bucket policy: {e}");
            return ExitCode::FAILURE;
        }
    };

    if findings.is_empty() {
        println!(
            "s3lint: no public-access statements found in '{}'",
            cli.bucket
        );
        ExitCode::SUCCESS
    } else {
        for f in &findings {
            let label = if f.severity == Severity::Critical {
                "CRITICAL"
            } else {
                "WARNING"
            };
            println!("[{label}] {}", f.message);
        }
        eprintln!(
            "\ns3lint: {} finding(s) in '{}'",
            findings.len(),
            cli.bucket
        );
        ExitCode::FAILURE
    }
}
