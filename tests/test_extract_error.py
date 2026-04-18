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
        """details.message is used when details.errors is empty."""
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
        assert msg == "Import of CG_GlobalSign_Atlas_R3_FEF8EDAA failed. Certificate is expired"

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
