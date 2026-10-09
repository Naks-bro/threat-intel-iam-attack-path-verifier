"""Explicit local-operator mode; alias is process configuration, not browser input."""

import os

from fastapi import FastAPI

from fyp_iam.api.app import create_app


def create_local_review_app() -> FastAPI:
    return create_app(local_reviewer_alias=os.environ.get("FYP_LOCAL_REVIEWER_ALIAS"))
