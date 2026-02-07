import argparse
import json
import sys
from pathlib import Path

if __package__ is None or __package__ == "":
	src_root = Path(__file__).resolve().parents[2]
	sys.path.insert(0, str(src_root))

from odt.core.pipeline import translate_command


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

	command = " ".join(args.command).strip()
	if not command:
		command = sys.stdin.read().strip()
		if not command:
			parser.error("No command provided via argument or stdin.")

	result = translate_command(
		command,
		refresh_mitre=args.refresh_mitre,
		include_secondary_techniques=args.include_secondary_techniques,
	)
	print(json.dumps(result, indent=2))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
