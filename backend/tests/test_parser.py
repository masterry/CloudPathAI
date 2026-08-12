from app.policy.parser import parse_policy_document


def test_parser_preserves_source_policy_arn() -> None:
    statements = parse_policy_document(
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        },
        source_policy_arn="arn:aws:iam::123456789012:policy/Test",
    )
    assert statements[0].source_policy_arn == "arn:aws:iam::123456789012:policy/Test"


def test_parser_flags_notaction_and_notresource() -> None:
    statements = parse_policy_document(
        {
            "Statement": {
                "Effect": "Allow",
                "NotAction": "iam:*",
                "NotResource": "arn:aws:s3:::private/*",
            }
        }
    )
    assert statements[0].unsupported_elements == ["NotAction", "NotResource"]
