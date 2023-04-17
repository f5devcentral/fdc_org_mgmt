# from github import Github, AppAuthentication
from dotenv import load_dotenv
from pathlib import Path
from gh import GitHubOrg
import os

load_dotenv()
GH_APP_ID = os.getenv("GH_APP_ID")
GH_INSTALLATION_ID = os.getenv("GH_INSTALLATION_ID")
GH_ORG = os.getenv("GH_ORG")
private_key = Path('fdc-user-mgmt.2023-04-15.private-key.pem', encoding="utf-8").read_text()

TEST_GH_USER = os.getenv("TEST_GH_USER")
TEST_GH_USER_NAME = os.getenv("TEST_GH_USER_NAME")
TEST_GH_USER_NOT_MEMBER = os.getenv("TEST_GH_USER_NOT_MEMBER")
TEST_GH_ORG_NAME = os.getenv("TEST_GH_ORG_NAME")


gh = GitHubOrg(GH_ORG, GH_APP_ID, private_key, GH_INSTALLATION_ID)

def test_gh():
    assert gh.get_org().name == TEST_GH_ORG_NAME

def test_gh_user():
    user = gh.get_user(TEST_GH_USER)
    assert user.name == TEST_GH_USER_NAME

def test_gh_is_member():
    assert gh.is_member(TEST_GH_USER) is True
    assert gh.is_member(TEST_GH_USER_NOT_MEMBER) is False

def test_gh_add_org_member():
    assert gh.add_org_member(TEST_GH_USER_NOT_MEMBER) is True
