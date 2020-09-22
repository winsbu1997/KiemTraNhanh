import logging

logging.basicConfig(level= logging.DEBUG, filename='Log/myapp.log',filemode= "a",format='%(asctime)s %(levelname)s:%(message)s')
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("this file has %d words", 45)
    logger.debug("kaka")
    logger.warning("Error")