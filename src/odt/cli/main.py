import argparse
import json
import sys

from odt.core.pipeline import translate_command


def build_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="Translate a command into MITRE ATT&CK T1059 mappings."
	)
	parser.add_argument(
		"command",
		nargs="?",
		help="Command string to analyze. If omitted, read from stdin.",
	)
	parser.add_argument(
		"--refresh-mitre",
		action="store_true",
		help="Refresh MITRE cache using attackcti.",
	)
	return parser


def main() -> int:
	parser = build_arg_parser()
	args = parser.parse_args()

	command = args.command
	if not command:
		command = sys.stdin.read().strip()
		if not command:
			parser.error("No command provided via argument or stdin.")

	result = translate_command(command, refresh_mitre=args.refresh_mitre)
	print(json.dumps(result, indent=2))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
