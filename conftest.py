import os


def _force_environment():
    os.environ["CMJR_PROVIDER"] = "generic"
    os.environ["CMJR_META_APP_ID"] = ""
    os.environ["CMJR_META_APP_SECRET"] = ""
    os.environ["CMJR_META_VERIFY_TOKEN"] = ""
    os.environ["CMJR_META_ACCESS_TOKEN"] = ""
    os.environ["CMJR_META_PHONE_NUMBER_ID"] = ""


_force_environment()