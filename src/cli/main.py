import argparse
import json
import sys
from pathlib import Path

# Ensure the src directory is in the Python path for imports when running this script directly, 
# allowing the use of absolute imports regardless of the execution context.
if __package__ is None or __package__ == "":
	src_root = Path(__file__).resolve().parent.parent
	sys.path.insert(0, str(src_root))

from core.pipeline import translate_command

# This script serves as the command-line interface for the ODT tool, 
# allowing users to input a command string and receive MITRE ATT&CK technique mappings in JSON format. 
# It supports reading from standard input if no command is provided as an argument, 
# and includes options to refresh the MITRE cache and include secondary techniques in the output.
def build_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="Translate a command into MITRE ATT&CK mappings (T1059 by default)."
	)
	parser.add_argument(
		"command",
		nargs=argparse.REMAINDER,
		help="Command string to analyze. If omitted, read from stdin.",
	)
	parser.add_argument(
		"--refresh-mitre",
		action="store_true",
		help="Refresh MITRE cache using attackcti.",
	)
	parser.add_argument(
		"--include-secondary-techniques",
		action="store_true",
		help="Include non-T1059 detections (e.g., T1027, T1218) in output.",
	)
	return parser


def main() -> int:
	parser = build_arg_parser()
	args = parser.parse_args()

<<<<<<< HEAD:src/cli/main.py
	# Combine command arguments into a single string, or read from stdin if no arguments provided
=======
>>>>>>> ce3c7b738c560637900a13e11e6395dae730cb32:src/odt/cli/main.py
	command = " ".join(args.command).strip()
	if not command:
		command = sys.stdin.read().strip()
		if not command:
			parser.error("No command provided via argument or stdin.")

	# Translate the command and print the results as formatted JSON
	result = translate_command(
		command,
		refresh_mitre=args.refresh_mitre,
		include_secondary_techniques=args.include_secondary_techniques,
	)
	# Output the result as pretty-printed JSON for easy readability and further processing if needed.
	print(json.dumps(result, indent=2))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
