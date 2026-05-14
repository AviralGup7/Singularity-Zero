import importlib
import logging

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def main():
    prov = importlib.import_module("src.recon.collectors.providers")
    logger.debug("providers module: %s", prov)
    logger.debug("providers.__file__: %s", getattr(prov, "__file__", None))
    logger.debug("providers attrs: %s", sorted([n for n in dir(prov) if not n.startswith("_")]))
    cr = getattr(prov, "crawler", None)
    logger.debug("crawler attr type: %s", type(cr))
    logger.debug("crawler module name: %s", getattr(cr, "__name__", None))
    logger.debug("crawler file: %s", getattr(cr, "__file__", None))


if __name__ == "__main__":
    main()
