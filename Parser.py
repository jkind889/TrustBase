from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from typing import Dict, List


RULES: Dict[str, Dict[str, List[str]]] = {
	"1. Data Collection (Schema & Ingestion)": {
		"Explicit Data": [
			"collect",
			"gather",
			"provided by you",
			"registration",
			"account creation",
		],
		"Automated Tracking": [
			"automatically collect",
			"tracking technologies",
			"cookies",
			"web beacons",
			"pixel tags",
			"Local Shared Objects",
		],
		"High-Risk Identifiers": [
			"IP address",
			"device identifier",
			"geolocation",
			"biometric data",
			"browsing history",
			"SSN",
			"government-issued ID",
		],
	},
	"2. Data Sharing (External Relationships)": {
		"The Entities": [
			"third party",
			"affiliates",
			"service providers",
			"subsidiaries",
			"business partners",
			"advertising networks",
			"data broker",
		],
		"The Actions": [
			"share",
			"don't Currently sell",
			"sell",
			"disclose",
			"transfer",
		],
		"The Exceptions (Loopholes for sharing)": [
			"business transfers",
			"legal requirements",
			"law enforcement",
			"subpoena",
			"merger",
			"bankruptcy",
		],
	},
	"3. User Rights & Controls (CRUD Operations)": {
		"Access & Deletion": [
			"right to access",
			"right to be forgotten",
			"request deletion",
			"rectify",
			"update your information",
		],
		"Consent Mechanisms": [
			"opt-out",
			"withdraw consent",
			"unsubscribe",
			"Do Not Sell or Share My Personal Information",
			"privacy choices",
		],
	},
	"4. Security & Retention (Storage & Archiving)": {
		"Security Standards": [
			"encryption",
			"Secure Socket Layer (SSL)",
			"anonymize",
			"pseudonymization",
			"safeguards",
		],
		"Timelines": [
			"retain",
			"retention period",
			"as long as necessary",
			"delete after",
		],
	},
	"5. Weasel Words (Red Flags)": {
		"Vague Qualifiers": [
			"may include",
			"might collect",
			"possibly",
			"could",
		],
		"Open-Ended Lists": [
			"such as",
			"including, but not limited to",
		],
		"Conditional Promises": [
			"commercially reasonable",
			"generally",
			"as applicable",
			"as needed",
		],
	},
}


@dataclass
class MatchResult:
	term: str
	count: int


def _pattern_for_term(term: str) -> str:
	escaped = re.escape(term)
	escaped = escaped.replace(r"\ ", r"\s+")
	escaped = escaped.replace(r"\,", r"\s*,\s*")
	if re.fullmatch(r"[A-Za-z\-]+", term):
		return rf"\b{escaped}\b"
	return escaped


def _count_matches(text: str, term: str) -> int:
	pattern = _pattern_for_term(term)
	return len(re.findall(pattern, text, flags=re.IGNORECASE))


def analyze_policy_text(text: str) -> Dict[str, object]:
	report: Dict[str, object] = {
		"summary": {},
		"categories": {},
		"risk_score": 0,
		"risk_level": "Low",
	}

	total_hits = 0
	weasel_hits = 0

	for category, subgroups in RULES.items():
		cat_total = 0
		subgroup_results: Dict[str, List[Dict[str, int]]] = {}

		for subgroup, terms in subgroups.items():
			hits: List[MatchResult] = []
			for term in terms:
				count = _count_matches(text, term)
				if count > 0:
					hits.append(MatchResult(term=term, count=count))
					cat_total += count
					total_hits += count
					if category.startswith("5."):
						weasel_hits += count

			hits.sort(key=lambda item: (-item.count, item.term.lower()))
			subgroup_results[subgroup] = [
				{"term": item.term, "count": item.count} for item in hits
			]

		report["categories"][category] = {
			"total_hits": cat_total,
			"subgroups": subgroup_results,
		}

	text_words = max(1, len(re.findall(r"\w+", text)))
	weasel_density = (weasel_hits / text_words) * 100

	risk_score = 0
	risk_score += min(30, report["categories"]["2. Data Sharing (External Relationships)"]["total_hits"] * 2)
	risk_score += min(25, report["categories"]["1. Data Collection (Schema & Ingestion)"]["total_hits"])
	risk_score += min(20, report["categories"]["4. Security & Retention (Storage & Archiving)"]["total_hits"])
	risk_score += min(25, int(weasel_density * 20))

	if risk_score >= 70:
		risk_level = "High"
	elif risk_score >= 40:
		risk_level = "Medium"
	else:
		risk_level = "Low"

	report["summary"] = {
		"total_hits": total_hits,
		"weasel_word_hits": weasel_hits,
		"weasel_density_percent": round(weasel_density, 3),
		"text_word_count": text_words,
	}
	report["risk_score"] = risk_score
	report["risk_level"] = risk_level

	sorted_categories = sorted(
		report["categories"].items(),
		key=lambda item: (-item[1]["total_hits"], item[0]),
	)
	report["categories_sorted"] = [
		{"category": category, "total_hits": details["total_hits"]}
		for category, details in sorted_categories
	]

	return report


def main() -> None:
	parser = argparse.ArgumentParser(
		description="Analyze privacy-policy text for collection, sharing, rights, security, and weasel words."
	)
	parser.add_argument("--text", help="Raw text to analyze.")
	parser.add_argument("--file", help="Path to a .txt file containing text to analyze.")
	args = parser.parse_args()

	if not args.text and not args.file:
		parser.error("Provide either --text or --file")

	if args.file:
		with open(args.file, "r", encoding="utf-8") as input_file:
			content = input_file.read()
	else:
		content = args.text or ""

	report = analyze_policy_text(content)
	print(json.dumps(report, indent=2))


if __name__ == "__main__":
	main()
