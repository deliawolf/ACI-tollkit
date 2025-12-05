import logging
import os
import sys
from logging.handlers import RotatingFileHandler

def setup_logger(name=None):
    """
    Sets up a logger with console (INFO) and file (DEBUG) handlers.
    
    Args:
        name (str, optional): Name of the logger. If None, returns the root logger.
        
    Returns:
        logging.Logger: Configured logger instance.
    """
    # Define log directory and file
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(project_root, 'logs')
    log_file = os.path.join(log_dir, 'app.log')

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Capture everything at root level

    # Check if handlers are already added to avoid duplicates
    if not logger.handlers:
        # 1. File Handler (Rotating, DEBUG level)
        # Rotates after 5MB, keeps 5 backup files
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # 2. Console Handler (INFO level)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        # Simple format for console to keep it clean for the user
        console_formatter = logging.Formatter('%(message)s') 
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger
