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
from core.batch_processor import load_batch_commands, process_batch_commands
from core.report_generator import generate_batch_report, generate_single_report

# This script serves as the command-line interface for the ODT tool, 
# allowing users to input a command string and receive MITRE ATT&CK technique mappings in JSON format. 
# It supports reading from standard input if no command is provided as an argument, 
# and includes options to refresh the MITRE cache and decode obfuscated commands.
def build_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="Translate command(s) into MITRE ATT&CK mappings across all supported techniques."
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
		"-o", "--output",
		type=str,
		help="Save output to JSON file in data/results/ directory. If omitted, print to stdout.",
	)
	parser.add_argument(
		"--batch-input",
		type=str,
		help="Path to batch input file (.json, .csv, .txt). If set, process all commands from file.",
	)
	parser.add_argument(
		"--batch-output",
		type=str,
		help="Output filename for batch results in data/results/. Default: batch_YYYYMMDD_HHMMSS.json",
	)
	parser.add_argument(
		"--batch-verbose",
		action="store_true",
		help="Print per-command progress while processing a batch.",
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
	parser.add_argument(
		"--generate-report",
		action="store_true",
		help="Generate HTML report (saved to data/reports/ directory).",
	)
	parser.add_argument(
		"--report-output",
		type=str,
		help="Custom path for HTML report. If omitted, uses default in data/reports/.",
	)
	return parser


def main() -> int:
	parser = build_arg_parser()
	args = parser.parse_args()

	# Combine command arguments into a single string, or read from stdin if no arguments provided
	if args.batch_input:
		commands = load_batch_commands(args.batch_input)
		batch_result = process_batch_commands(
			commands,
			refresh_mitre=args.refresh_mitre,
			decode=args.decode,
			verbose=args.batch_verbose,
		)
		batch_json = json.dumps(batch_result, indent=2)

		output_dir = Path(__file__).resolve().parent.parent.parent / "data" / "results"
		output_dir.mkdir(parents=True, exist_ok=True)

		if args.batch_output:
			output_filename = args.batch_output
		else:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			output_filename = f"batch_{timestamp}.json"

		output_path = output_dir / output_filename
		with open(output_path, "w", encoding="utf-8") as f:
			f.write(batch_json)
		print(f"Batch results saved to: {output_path}")
		
		# Generate HTML report if requested
		if args.generate_report:
			report_dir = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
			report_dir.mkdir(parents=True, exist_ok=True)
			
			if args.report_output:
				report_path = args.report_output
			else:
				timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
				report_path = str(report_dir / f"batch_{timestamp}.html")
			
			generate_batch_report(batch_result, report_path)
			print(f"Report generated: {report_path}")
		
		return 0

	command = " ".join(args.command).strip()
	if not command:
		command = sys.stdin.read().strip()
		if not command:
			parser.error("No command provided via argument or stdin.")

	# Translate the command and print the results as formatted JSON
	result = translate_command(
		command,
		refresh_mitre=args.refresh_mitre,
		decode=args.decode,
	)
	
	from core.output import format_detections_with_separator

	# Generate HTML report if requested
	if args.generate_report:
		report_dir = Path(__file__).resolve().parent.parent.parent / "data" / "reports"
		report_dir.mkdir(parents=True, exist_ok=True)
		
		if args.report_output:
			report_path = args.report_output
		else:
			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			report_path = str(report_dir / f"analysis_{timestamp}.html")
		
		generate_single_report(result, report_path)
		print(f"Report generated: {report_path}")
		return 0

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
