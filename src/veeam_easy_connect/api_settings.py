api_settings = {
    "o365": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/json",
        },
        "port": "4443",
        "url": "/v6/Token",
        "api_version": "v6",
    },
    "aws": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-api-version": "1.2-rev0",
        },
        "port": "11005",
        "url": "/api/v1/token",
        "api_version": "v1",
    },
    "ent_man": {"port": "9398", "url": "/api/sessionMngr/?v=latest"},
    "vbr": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-api-version": "1.0-rev2",
        },
        "port": "9419",
        "url": "/api/oauth2/token",
        "api_version": "v1",
    },
    "spc": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/json",
        },
        "port": "1280",
        "url": "/api/v3/token",
        "api_version": "v3",
    },
    "azure": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        },
        "url": "/api/oauth2/token",
        "api_version": "v3",
    },
    "gcp": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-api-version": "1.0-rev0",
        },
        "port": "13140",
        "url": "/api/v1/token",
        "api_version": "v1",
    },
    "vone": {
        "headers": {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-api-version": "1.0-rev2",
        },
        "port": "1239",
        "url": "/api/token",
        "api_version": "v2",
    },
}
