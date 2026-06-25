from .BaseController import BaseController
from modules.sigma import SigmaConversionEngine
import logging


class SigmaController(BaseController):

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger("uvicorn.error")
        self.engine = SigmaConversionEngine()

    def validate(self, sigma_rule: str, filename: str = None):
        return self.engine.validate(
            sigma_rule=sigma_rule,
            filename=filename,
        )

    def convert(self, sigma_rule: str, platforms: list = None, filename: str = None):
        return self.engine.convert(
            sigma_rule=sigma_rule,
            platforms=platforms,
            filename=filename,
        )

    def bulk_convert(self, rules: list, platforms: list = None):
        return self.engine.bulk_convert(
            rules=rules,
            platforms=platforms,
        )

