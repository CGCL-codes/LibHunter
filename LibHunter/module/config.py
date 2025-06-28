import logging
import logging.handlers
import multiprocessing
import os.path

# Operating parameters related config
# Maximum number of processes used in detection:
max_thread_num = multiprocessing.cpu_count()
# max_thread_num = 2

pickle_dir = "dex_pickles"
if not os.path.exists(pickle_dir):
    os.makedirs(pickle_dir)

# Detection level: ("lib"=TPL level detection; "lib_version"=TPL version level detection)
# Default is TPL version level detection. Need to provide (TPL version,TPL) mapping in `conf/lib_name_map.csv` (We have provide the mapping for the ground truth dataset)
detect_type = "lib_version"

# class similarity threshold (theta)
class_similar = 1
method_similar = 0.75
# lib similarity threahold (theta2)
lib_similar = 0.85
lib_similar = 0.1

log_file = "log.txt"


def clear_log():
    if os.path.exists(log_file):
        os.remove(log_file)


def setup_logger():
    logger = logging.getLogger()
    if not logger.handlers:  # Check if the logger already has handlers
        if multiprocessing.current_process().name == "MainProcess":
            logger.setLevel(logging.INFO)
            fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
            formatter = logging.Formatter('%(asctime)s - %(name)s - [%(lineno)d] - %(message)s')
            fh.setFormatter(formatter)
            logger.addHandler(fh)
    return logger


def listener_process(queue):
    logger = logging.getLogger()
    fh = logging.FileHandler(log_file, 'a', encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(name)s - [%(lineno)d] - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)

    while True:
        record = queue.get()
        if record is None:  # None is a sentinel to end logging
            break
        logger.handle(record)

    logger.removeHandler(fh)
    fh.close()


def worker_init(queue):
    h = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.handlers.clear()  # Clear existing handlers
    root.addHandler(h)
    root.setLevel(logging.INFO)
