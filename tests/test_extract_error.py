"""Tests for extract_error_message utility."""

from unittest.mock import MagicMock

from scm_chainguard.scm import extract_error_message


def _mock_response(json_body: dict, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = json_body
    resp.text = text or str(json_body)
    return resp


class TestExtractErrorMessage:
    def test_details_message_extracted(self):
        """details.message is used when details.errors is empty, enriched with extras."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "code": "API_I00013",
                        "message": "Your configuration is not valid. Please review the error message for more details.",
                        "details": {
                            "errorType": "Operation Failed",
                            "message": "Import of CG_GlobalSign_Atlas_R3_FEF8EDAA failed. Certificate is expired",
                            "errors": [],
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert "Import of CG_GlobalSign_Atlas_R3_FEF8EDAA failed. Certificate is expired" in msg
        assert "errorType=Operation Failed" in msg

    def test_details_message_no_extras_unchanged(self):
        """details.message with no extra fields produces a clean message."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "message": "Generic",
                        "details": {
                            "message": "Certificate is expired",
                            "errors": [],
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert msg == "Certificate is expired"

    def test_detail_errors_array_preferred(self):
        """details.errors[] array takes priority over details.message."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "message": "Generic error",
                        "details": {
                            "message": "Should not be used",
                            "errors": [{"msg": "'bad-cert' is not a valid reference"}],
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert "'bad-cert' is not a valid reference" in msg

    def test_detail_errors_only_msg_unchanged(self):
        """Error entries with just msg produce the same output as before."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "message": "Invalid Object",
                        "details": {
                            "errors": [{"msg": "simple error"}],
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert msg == "simple error"

    def test_detail_errors_with_extra_fields(self):
        """Error entries with fields beyond msg include them as key=value."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "message": "Invalid Object",
                        "details": {
                            "errors": [
                                {
                                    "msg": "reference conflict",
                                    "code": "REF_001",
                                    "path": "ssl-decryption-settings",
                                }
                            ],
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert "reference conflict" in msg
        assert "code=REF_001" in msg
        assert "path=ssl-decryption-settings" in msg

    def test_detail_errors_extras_only(self):
        """Error entries with no msg but other fields are still included."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "message": "Fallback",
                        "details": {
                            "errors": [{"code": "REF_001", "path": "/config"}],
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert "code=REF_001" in msg
        assert "path=/config" in msg

    def test_fallback_to_top_level_message(self):
        """Falls back to _errors[0].message when no details exist."""
        resp = _mock_response({"_errors": [{"message": "Name Not Unique", "details": {}}]})
        msg = extract_error_message(resp)
        assert msg == "Name Not Unique"

    def test_fallback_to_resp_text(self):
        """Falls back to resp.text when JSON has no _errors."""
        resp = _mock_response({"unexpected": "format"}, text="raw error text")
        msg = extract_error_message(resp)
        assert msg == "raw error text"

    def test_non_json_response(self):
        """Falls back to resp.text when response is not JSON."""
        resp = MagicMock()
        resp.json.side_effect = ValueError("No JSON")
        resp.text = "Internal Server Error"
        msg = extract_error_message(resp)
        assert msg == "Internal Server Error"

    def test_none_values_excluded_from_extras(self):
        """Fields with None values are excluded from extras."""
        resp = _mock_response(
            {
                "_errors": [
                    {
                        "message": "Error",
                        "details": {
                            "message": "some error",
                            "errorType": "Conflict",
                            "extra": None,
                        },
                    }
                ]
            }
        )
        msg = extract_error_message(resp)
        assert "errorType=Conflict" in msg
        assert "extra" not in msg
