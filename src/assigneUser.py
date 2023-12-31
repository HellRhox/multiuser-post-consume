#!/usr/bin/env python3

import os
import json
import re
import argparse

import requests

filepattern = "^[\w,\s-]+\.[A-Za-z]{2,4}$"


def _set_auth_tokens(paperless_url: str, username: str, password: str, timeout: float, session: requests.Session):
    credentials = {
        "username": username,
        "password": password
    }

    response = session.get(paperless_url, timeout=timeout)
    response.raise_for_status()

    csrf_token = response.cookies["csrftoken"]

    response = session.post(
        paperless_url + "/api/token/",
        data=json.dumps(credentials),
        headers={
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json"
        },
        timeout=timeout,
    )
    response.raise_for_status()

    api_token = response.json()["token"]

    session.headers.update(
        {"Authorization": f"Token {api_token}", f"X-CSRFToken": csrf_token}
    )


def get_config():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-u", "--url", help="url to the paperless-ngx instance", required=True)
    parser.add_argument("-n", "--name", help="username of the consumption user", required=True)
    parser.add_argument("-p", "--password", help="password of the consumption user", required=True)
    args = parser.parse_args()
    return vars(args)


def get_user_from_path(path: str):
    print(path)
    splitpath = path.split("/")
    if len(splitpath) > 6:
        splitpath = path.split("/")
        if re.search(filepattern, splitpath[len(splitpath) - 1]):
            return splitpath[len(splitpath) - 2]
        else:
            return splitpath[len(splitpath) - 1]
    else:
        return None


def read_consume_path():
    file = open('/usr/src/paperless/scripts/realsource.txt', 'r')
    line = file.readline()
    file.close()
    return line


def get_user_id(username: str):
    response = sess.get(paperless_url + f"/api/users/",
                        headers={
                            "Content-Type": "application/json"
                        },
                        timeout=timeout
                        )
    response.raise_for_status()
    response = response.json()

    for result in response["results"]:
        user_match = result["username"].lower() == username.lower()
        if user_match:
            print("user matched")
            return result["id"]

    print("user not matched")
    return None


if __name__ == "__main__":
    config = get_config()
    print(config)
    paperless_url = config.get("url")
    paperless_username = config.get("name")
    paperless_password = config.get("password")
    timeout = 50.0

    with requests.Session() as sess:
        # Set tokens for the appropriate header auth
        _set_auth_tokens(paperless_url, paperless_username, paperless_password,
                         timeout, sess)
        # Get the PK as provided via post-consume
        doc_pk = int(os.environ["DOCUMENT_ID"])
        doc_sourcepath = read_consume_path()

        user = get_user_from_path(doc_sourcepath)
        print(user)
        if user is None:
            exit()
        else:
            userId = get_user_id(user)
            if userId is None:
                exit()

            # Update the document
            resp = sess.patch(
                paperless_url + f"/api/documents/{doc_pk}/",
                data=json.dumps(
                    {
                        "owner": userId,
                    }
                ),
                headers={
                    "Content-Type": "application/json"
                },
                timeout=timeout
            )
            resp.raise_for_status()
