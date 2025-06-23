from logger.log_manager import LogManager

def test_logger():

    log_manager = LogManager.get_instance()
    logger = log_manager.get_logger()

    logger.debug("TEST DEBUG")
    logger.info("TEST INFO")
    logger.warning("TEST WARNIGN")
    logger.error("TEST ERROR")
    logger.critical("TEST CRITICAL")

    try:
        1/0
    except ZeroDivisionError as e:
        logger.error("TEST EXCEPTION", exc_info = True)

if __name__ == "__main__":
    #test_logger()
    pass