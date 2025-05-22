import threading
import re
import logging
import argparse
import sys
import concurrent.futures

from typing import List, Optional, TextIO

"""
Author: Olof Magnusson
Date: 2025-05-22
A program that searches for rules using the msg header for faster lookups of service names in inventory lists
"""
BANNER = r"""
   _____                 _             __ _           _
  / ____|               (_)           / _(_)         | |
 | (___   ___ _ ____   ___  ___ ___  | |_ _ _ __   __| | ___ _ __
  \___ \ / _ \ '__\ \ / / |/ __/ _ \ |  _| | '_ \ / _` |/ _ \ '__|
  ____) |  __/ |   \ V /| | (_|  __/ | | | | | | | (_| |  __/ |
 |_____/ \___|_|    \_/ |_|\___\___| |_| |_|_| |_|\__,_|\___|_|


  @olofmagn(1.0)

        """
class LoggerManager:
    def __init__(self, name: str = __name__, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Avoid duplicate handlers if logger already has one
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def get_logger(self):
        return self.logger

class SuricataRuleSearcher:
    def __init__(self, input_file: str, output_file: Optional[str], service_name: str, num_threads: int = 4):
        """
        Initializes the SuricataRuleSearcher object.

        Args:
        - input_file (str): Path to the input Suricata rule file.
        - output_file (str): Path to the output file for saving matched rules.
        - service_name (str): The service name to search for in the 'msg' field.
        - num_threads (int): The number of threads to use for processing.
        """
        self.logger = LoggerManager(self.__class__.__name__).get_logger()
        self.input_file = input_file
        self.output_file = output_file
        self.service_name = service_name
        self.num_threads = num_threads
        self.service_pattern = re.compile(r'msg:"([^"]+)"', re.IGNORECASE)

    def load_file(self) -> List[str]:
        try:
            with open(self.input_file, 'r', encoding='utf-8') as infile:
                lines = infile.readlines()
            return lines
        except FileNotFoundError:
            self.logger.error(f"File not found: {self.input_file}. Perhaps misspelled? Exiting the program.")
            sys.exit(1)
        except IOError:
            self.logger.error(f"I/O error occured when reading {self.input_file}. Exiting the program")
            sys.exit(1)

    def _validate_service_name(self) -> bool:
        if not self.service_name:
            self.logger.error(f"No service name provided: {self.service_name}. Exiting the program")
            return False
        return True

    def _search_for_service_in_chunk(self, chunk: List[str]) -> int:
        """
        Searches for the specified service name in a chunk of the Suricata rule file.

        Args:
        - chunk (list): A chunk of lines to process.
        """
        # Console or printout to file depending on the arguments provided
        if not self.output_file:
            output=self._find_matches(chunk)
        else:
            with open(self.output_file, 'a', encoding='utf-8') as outfile:
                output=self._find_matches(chunk, outfile)

        return output

    def _find_matches(self, chunk: List[str], output_file: Optional[TextIO] = None) -> int:
        if not self.service_name:
            return 0

        matched_lines = 0
        service_name_lower = self.service_name.lower()

        for line in chunk:
            match = self.service_pattern.search(line)
            if not match:
                continue

            msg_content = match.group(1)
            if not msg_content or service_name_lower not in msg_content.lower():
                continue

            matched_lines += 1

            if output_file:
                output_file.write(line)
            else:
                self.logger.info(line.rstrip())

        return matched_lines

    def process_file_in_chunks(self) -> None:
        """
        Processes the Suricata rule file in chunks and uses threading to search for the specific service.
        """
        if not self._validate_service_name():
            sys.exit(1)

        if not self._validate_service_name():
            sys._exit(1)

        self.logger.info(f"Starting search for service '{self.service_name}' in file '{self.input_file}' with {self.num_threads} threads...")

        lines = self.load_file()
        # Make sure the workload is evenly distributed among threads
        chunks = self._split_lines_evenly(lines, self.num_threads)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            total_matches = 0 
            futures = []
            for chunk in chunks:
                if chunk:
                    futures.append(executor.submit(self._search_for_service_in_chunk, chunk))

            for future in concurrent.futures.as_completed(futures):
                try:
                    matches = future.result()
                    total_matches += matches 
                except Exception as e:
                    logging.error(f"Error in thread {e}")
            
            self.logger.info(f"Total matches {total_matches} for the service name {self.service_name}")

    def _split_lines_evenly(self, lines: List[str], num_chunks: int) -> List[List[str]]:
        avg = len(lines) // num_chunks
        remainder = len(lines) % num_chunks
        chunks = []
        start = 0

        for i in range(num_chunks):
            end = start + avg + (1 if i < remainder else 0)
            chunks.append(lines[start:end])
            start = end

        return chunks

class ArgumentParser:
    """
    Handles argument parsing and script execution.
    """
    def __init__(self):
        self.parser = self.create_parser()

    def create_parser(self) -> argparse.ArgumentParser:
        """
        Configures the argument parser with expected arguments.
        """
        parser = argparse.ArgumentParser(
            description="Search for service names in Suricata rule files",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=BANNER
        )

        parser.add_argument(
            '-i', '--input_file', 
            required=True,
            help="Path to the input Suricata rule file"
        )
        parser.add_argument(
            '-o', '--output_file',
            help="Path to the output file for saving matched rules (optional)"
        )
        parser.add_argument(
            '-s', '--service_name',
            required=True,
            help="Service name to search for in the 'msg' field"
        )
        parser.add_argument(
            '-t', '--threads', 
            type=int,
            default=4,
            help="Number of threads to use (default: 4)"
        )

        return parser

    def parse_args(self) -> argparse.Namespace:
        """
        Parse and return command-line arguments.
        """

        return self.parser.parse_args()


class SuricataServiceSearchApp:
    def __init__(self):
        """
        Initializes the application, including argument parsing and searcher.
        """
        parser = ArgumentParser()
        self.args = parser.parse_args()

        self.searcher = SuricataRuleSearcher(
                input_file=self.args.input_file,
                output_file=self.args.output_file,
                service_name=self.args.service_name,
                num_threads=self.args.threads,
                )

    def run(self) -> None:
        """
        Runs the Suricata rule search application.
        """
        self.searcher.process_file_in_chunks()

def main():
    """
    The entry point for the script execution.
    """
    try:
        app = SuricataServiceSearchApp()
        app.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
