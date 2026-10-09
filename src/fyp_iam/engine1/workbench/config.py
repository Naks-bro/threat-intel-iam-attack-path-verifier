"""Environment configuration. An empty URL means the database is not configured."""


def database_url_from_env() -> str | None:
    from fyp_iam.persistence.urls import application_database_url

    return application_database_url()
