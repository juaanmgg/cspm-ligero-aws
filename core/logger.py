"""Central logging configuration for the CSPM application."""

import logging


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure application logging and return the CSPM logger."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("cspm")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    return logger
