import multiprocessing
from datetime import datetime
import logging
from multiprocessing.queues import Queue
from logging.handlers import QueueHandler
from .storage_helper import StorageLocation

__all__ = ['global_logger', 'get_child_logger', 'Agent4VulLogger']

# Define log level names to their corresponding values
level_names = {
    'CRITICAL': 50,
    'FATAL': 50,
    'ERROR': 40,
    'WARNING': 30,
    'WARN': 30,
    'INFO': 20,
    'DEBUG': 10,
    'NOTSET': 0
}

class Agent4VulLogger:

    def __init__(self):
        logger = logging.getLogger('Agent4VulLogger')
        log_level = "INFO"
        if log_level in level_names:
            logger.setLevel(level_names[log_level])
        else:
            raise ValueError(f"Invalid log level: {log_level}")

        # logging file
        logging_dir = StorageLocation.logging_dir()
        log_file_formatter = logging.Formatter(
            '%(asctime)s - %(filename)s:%(lineno)d - [%(levelname)s]: %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        file_handler = logging.FileHandler(
            logging_dir / datetime.now().strftime('log_%Y-%m-%d_%H_%M.log'),
            mode='a',
            encoding='utf-8'
        )
        file_handler.setFormatter(log_file_formatter)

        # console
        console_formatter = logging.Formatter(
            '%(asctime)s - [%(levelname)s]: %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p'
        )
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(console_formatter)

        # add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        self.logger = logger

    def get_logger(self):
        return self.logger

    @staticmethod
    def get_child_logger(queue: Queue, logger_name: str = 'Agent4VulLogger'):
        """
        Called in child process: remove all inherited old handlers, keep only one QueueHandler
        """
        logger = logging.getLogger(logger_name)

        # 1. First remove old handlers to avoid "local+queue" double writing
        for h in list(logger.handlers):
            logger.removeHandler(h)
            try:           # Release file handle
                h.close()
            except Exception:
                pass

        # 2. Only attach one QueueHandler
        qh = QueueHandler(queue)
        qh.setLevel(logger.level)
        logger.addHandler(qh)
        logger.propagate = False  # Prevent bubbling to root to create more copies
        return logger

global_logger = Agent4VulLogger().get_logger()
get_child_logger = Agent4VulLogger.get_child_logger