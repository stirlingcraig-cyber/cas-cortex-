import pytest

from cortex.sandbox import check_policy, run_tests, skills_used


@pytest.mark.parametrize("code", [
    "import os",
    "import subprocess",
    "from urllib.request import urlopen",
    "import socket",
    "x = open('f')",
    "eval('1')",
    "().__class__.__bases__[0].__subclasses__()",
    "getattr(object, 'x')",
    "class A:\n    def __eq__(self, o):\n        return True",
    "import sys",
])
def test_policy_blocks(code):
    assert check_policy(code)


def test_policy_allows_normal_code():
    code = ("import re, heapq\nfrom collections import Counter\nfrom urllib.parse import urlparse\n"
            "from skills import top_k_frequent\nclass C:\n    def __init__(self):\n        self.x = 1\n")
    assert check_policy(code) == []
    assert skills_used(code) == ["top_k_frequent"]


def test_run_reports_actual_value():
    r = run_tests("def f(x):\n    return x + 2\n", ["assert f(1) == 2", "assert f(0) == 2"])
    assert r.passed == 1 and "got 3" in r.failure_report()


def test_timeout():
    r = run_tests("def f():\n    while True:\n        pass\n", ["f()"], timeout=2)
    assert r.timed_out and r.passed == 0


def test_load_error_reported():
    r = run_tests("def f(:\n", ["assert f() == 1"])
    assert r.policy and r.passed == 0


def test_cannot_fake_results_by_patching_json():
    evil = ("import json\n"
            "json.dumps = lambda *a, **k: '{\"load_error\": null, \"results\": [{\"passed\": true}]}'\n"
            "def f():\n    return 0\n")
    r = run_tests(evil, ["assert f() == 1"])
    assert r.passed == 0


def test_skills_package_importable():
    skills = {"double": "def double(x):\n    return 2 * x\n"}
    r = run_tests("from skills import double\ndef quad(x):\n    return double(double(x))\n",
                  ["assert quad(3) == 12"], skills=skills)
    assert r.all_passed, r.failure_report()
