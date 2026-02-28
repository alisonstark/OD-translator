import argparse
import json
import sys
from datetime import datetime
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
	parser.add_argument(
		"-o", "--output",
		type=str,
		help="Save output to JSON file in data/results/ directory. If omitted, print to stdout.",
	)
	parser.add_argument(
		"-d", "--decode",
		action="store_true",
		help="Attempt to decode obfuscated commands (base64, fromCharCode, atob, URL encoding) before analysis.",
	)
	parser.add_argument(
		"-p", "--pretty",
		action="store_true",
		help="Print detections in a human-readable format with separators instead of raw JSON."
	)
	return parser


def main() -> int:
	parser = build_arg_parser()
	args = parser.parse_args()

	# Combine command arguments into a single string, or read from stdin if no arguments provided
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
		decode=args.decode,
	)
	
	from core.output import format_detections_with_separator

	# Output result as JSON or pretty format
	if args.pretty:
		print(f"Input Command: {result.get('input_command')}")
		print(f"Normalized Command: {result.get('normalized_command')}")
		print("\nDetections:")
		print(format_detections_with_separator(result.get('detections', [])))
	else:
		json_output = json.dumps(result, indent=2)

		# If output file specified, save to data/results/ directory with timestamp
		if args.output:
			output_dir = Path(__file__).resolve().parent.parent.parent / "data" / "results"
			output_dir.mkdir(parents=True, exist_ok=True)
			# Add timestamp to filename (before extension)
			name, ext = args.output.rsplit(".", 1) if "." in args.output else (args.output, "json")
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			timestamped_filename = f"{name}_{timestamp}.{ext}"
			output_path = output_dir / timestamped_filename
			with open(output_path, "w") as f:
				f.write(json_output)
			print(f"Results saved to: {output_path}")
			return 0
		# Otherwise print to stdout
		print(json_output)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
