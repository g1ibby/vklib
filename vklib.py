#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import http.cookiejar
import urllib.request, urllib.error, urllib.parse
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlparse
from html.parser import HTMLParser
from datetime import datetime, timedelta
import webbrowser
import pickle


AUTH_FILE = '.auth_data'

class FormParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.url = None
        self.params = {}
        self.in_form = False
        self.form_parsed = False
        self.method = "GET"

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "form":
            if self.form_parsed:
                raise RuntimeError("Second form on page")
            if self.in_form:
                raise RuntimeError("Already in form")
            self.in_form = True
        if not self.in_form:
            return
        attrs = dict((name.lower(), value) for name, value in attrs)
        if tag == "form":
            self.url = attrs["action"]
            if "method" in attrs:
                self.method = attrs["method"].upper()
        elif tag == "input" and "type" in attrs and "name" in attrs:
            if attrs["type"] in ["hidden", "text", "password"]:
                self.params[attrs["name"]] = attrs["value"] if "value" in attrs else ""

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form":
            if not self.in_form:
                raise RuntimeError("Unexpected end of <form>")
            self.in_form = False
            self.form_parsed = True

def auth(client_id, scope, email = '', password = ''):
    def split_key_value(kv_pair):
        kv = kv_pair.split("=")
        return kv[0], kv[1]

    # Authorization form
    def auth_user(email, password, client_id, scope, opener):

        response = opener.open(
            "http://oauth.vk.com/oauth/authorize?" + \
            "redirect_uri=http://oauth.vk.com/blank.html&response_type=token&" + \
            "client_id=%s&scope=%s&display=wap" % (client_id, ",".join(scope))
            )

        doc = response.read()
        parser = FormParser()
        parser.feed(doc.decode('utf8'))
        parser.close()
        if not parser.form_parsed or parser.url is None or "pass" not in parser.params or \
          "email" not in parser.params:
              raise RuntimeError("Something wrong")
        parser.params["email"] = email
        parser.params["pass"] = password
        if parser.method == "POST":
            response = opener.open(parser.url, urllib.parse.urlencode(parser.params).encode('utf8'))
        else:
            raise NotImplementedError("Method '%s'" % parser.method)
        return response.read(), response.geturl()

    # Permission request form
    def give_access(doc, opener):
        parser = FormParser()
        parser.feed(doc.decode('utf8'))
        parser.close()
        if not parser.form_parsed or parser.url is None:
              raise RuntimeError("Something wrong")
        if parser.method == "POST":
            response = opener.open(parser.url, urllib.parse.urlencode(parser.params).encode('utf8'))
        else:
            raise NotImplementedError("Method '%s'" % parser.method)
        return response.geturl()

    def get_saved_auth_params():
        access_token = None
        user_id = None
        try:
            with open(AUTH_FILE, 'rb') as pkl_file:
                token = pickle.load(pkl_file)
                expires = pickle.load(pkl_file)
                uid = pickle.load(pkl_file)
            if datetime.now() < expires:
                access_token = token
                user_id = uid
        except IOError:
            pass
        return access_token, user_id

    def save_auth_params(access_token, expires_in, user_id):
        expires = datetime.now() + timedelta(seconds=int(expires_in))
        with open(AUTH_FILE, 'wb') as output:
            pickle.dump(access_token, output)
            pickle.dump(expires, output)
            pickle.dump(user_id, output)

    access_token, user_id = get_saved_auth_params()
    if not access_token or not user_id:
        if not isinstance(scope, list):
            scope = [scope]
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.HTTPRedirectHandler())
        doc, url = auth_user(email, password, client_id, scope, opener)
        if urlparse(url).path != "/blank.html":
            # Need to give access to requested scope
            url = give_access(doc, opener)
        if urlparse(url).path != "/blank.html":
            raise RuntimeError("Expected success here")
        answer = dict(split_key_value(kv_pair) for kv_pair in urlparse(url).fragment.split("&"))
        print(answer)
        if "access_token" not in answer or "user_id" not in answer:
            raise RuntimeError("Missing some values in answer")
        save_auth_params(answer["access_token"], answer["expires_in"], answer["user_id"])
        access_token = answer["access_token"]
        user_id = answer["user_id"]

    return access_token, user_id

