"""Replaces the desktop-only dependencies with harmless fakes so the tests run anywhere
(Linux CI included) and can never touch the real Windows credential store or a real API key."""
import sys
import types

_store = {}

def install():
    webview = types.ModuleType("webview")
    webview.create_window = lambda *a, **k: None
    webview.start = lambda *a, **k: None
    sys.modules["webview"] = webview

    plyer = types.ModuleType("plyer")
    plyer.notification = types.SimpleNamespace(notify=lambda *a, **k: None)
    sys.modules["plyer"] = plyer

    keyring = types.ModuleType("keyring")
    keyring.get_password = lambda service, user: _store.get((service, user))
    keyring.set_password = lambda service, user, value: _store.__setitem__((service, user), value)
    keyring.delete_password = lambda service, user: _store.pop((service, user), None)
    sys.modules["keyring"] = keyring

install()
