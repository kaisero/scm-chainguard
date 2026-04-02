"""CCADB HTTP client for downloading metadata and PEM CSVs."""

from __future__ import annotations

import logging

import requests

logger = logging.getLogger(__name__)

METADATA_URL = (
    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv3"
)
PEM_URL_TEMPLATE = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade={decade}"
DECADES = ("20000", "20100", "20200")


class CcadbClient:
    """Downloads CCADB CSV data over HTTP."""

    def __init__(self, timeout: int = 120):
        self._timeout = timeout
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> CcadbClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def download_metadata_csv(self) -> str:
        """Download the CCADB AllCertificateRecordsReport CSV."""
        logger.info("Downloading CCADB metadata CSV from %s", METADATA_URL)
        resp = self._session.get(METADATA_URL, timeout=self._timeout)
        resp.raise_for_status()
        logger.info("Downloaded %d bytes of metadata.", len(resp.content))
        return resp.text

    def download_pem_csv(self, decade: str) -> str:
        """Download PEM CSV for a single decade."""
        url = PEM_URL_TEMPLATE.format(decade=decade)
        logger.info("Downloading PEM CSV for decade %s", decade)
        resp = self._session.get(url, timeout=180)
        resp.raise_for_status()
        logger.info("Downloaded %d bytes for decade %s.", len(resp.content), decade)
        return resp.text

    def download_all_pem_csvs(self) -> list[str]:
        """Download PEM CSVs for all decades."""
        return [self.download_pem_csv(d) for d in DECADES]
