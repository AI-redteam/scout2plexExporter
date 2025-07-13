#!/usr/bin/env python3
"""
Scout Suite to PlexTrac Converter (v2.2.2)

A production-ready tool to convert Scout Suite JSON report output into a
feature-rich, PlexTrac-compliant CSV format. This version focuses on providing
rich, detailed descriptions and accurate asset identification (ARN/Name).
"""

import json
import csv
import argparse
import os
import sys
import re
from pathlib import Path

# --- Constants for colored output ---
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class ScoutSuiteToPlexTrac:
    """
    Converter class for Scout Suite to PlexTrac format.
    Handles advanced filtering, deduplication, and evidence extraction.
    """

    # --- Mappings ---
    SEVERITY_MAPPING = {
        'danger': 'Critical',
        'warning': 'High',
        'caution': 'Medium',
        'info': 'Low',
        'informational': 'Informational'
    }
    SEVERITY_RANK = {
        'Critical': 5, 'High': 4, 'Medium': 3,
        'Low': 2, 'Informational': 1
    }
    ASSET_ID_KEYS = [
        'Arn', 'arn', 'ARN', 'DBInstanceIdentifier', 'id', 'name',
        'BucketName', 'ClusterIdentifier', 'FunctionName', 'LoadBalancerName',
        'GroupId', 'VpcId', 'SubnetId', 'InstanceId', 'VolumeId', 'SnapshotId'
    ]

    def __init__(self, input_file, output_file=None, **kwargs):
        """Initializes the converter with files and processing options."""
        self.input_file = Path(input_file)
        if output_file:
            self.output_file = Path(output_file)
        else:
            self.output_file = self.input_file.with_name(f"{self.input_file.stem}_plextrac.csv")

        self.min_severity = kwargs.get('min_severity')
        self.regions_filter = kwargs.get('regions') or []
        self.explode_findings = kwargs.get('explode_findings', False)

        self.plextrac_headers = [
            'title', 'severity', 'status', 'description', 'recommendations',
            'references', 'affected_assets', 'tags', 'cvss_temporal',
            'cwe', 'cve', 'category'
        ]

    def _log(self, message, level='INFO'):
        """Prints a formatted log message."""
        color_map = {'INFO': Colors.BLUE, 'SUCCESS': Colors.GREEN, 'WARN': Colors.YELLOW, 'ERROR': Colors.RED}
        print(f"{color_map.get(level, Colors.BLUE)}[{level.ljust(7)}] {Colors.ENDC}{message}")

    def _strip_html(self, text):
        """Removes common HTML tags from a string for cleaner output."""
        return re.sub('<[^<]+?>', '', text).strip() if text else ""

    def _resolve_path(self, data, path_str):
        """Resolves a dot-separated path string within a nested dictionary."""
        try:
            value = data
            for key in path_str.split('.'):
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else: return None
            return value
        except (KeyError, IndexError, TypeError):
            return None

    def _get_asset_details(self, scout_data, item_path):
        """
        Resolves an item path to find the resource's true identifier (ARN/Name)
        and formats its key details for the description field.
        """
        parent_path = ".".join(item_path.split('.')[:-1])
        resource_obj = self._resolve_path(scout_data, parent_path)

        if not isinstance(resource_obj, dict):
            return item_path.split('.')[-2], 'unknown', "*No details available.*"

        asset_id = next((resource_obj[key] for key in self.ASSET_ID_KEYS if key in resource_obj and resource_obj[key]), None)
        if not asset_id:
            asset_id = parent_path.split('.')[-1]

        # FIX: Revert to parsing region from the path for reliability
        region_match = re.search(r'\.regions\.([\w-]+)\.', item_path)
        region = region_match.group(1) if region_match else 'global'

        details_to_show = {k: v for k, v in resource_obj.items() if isinstance(v, (str, int, bool)) and k not in ['id', 'name', 'arn']}
        formatted_details = "\n".join(f"* **{k}:** {v}" for k, v in sorted(details_to_show.items()))
        
        return asset_id, region, formatted_details

    def parse_report(self):
        """Parses the Scout Suite report."""
        self._log(f"Reading report: {self.input_file}")
        try:
            content = self.input_file.read_text(encoding='utf-8')
            json_content = content.split('=', 1)[1].strip() if content.strip().startswith('scoutsuite_results') else content
            data = json.loads(json_content)
            if 'services' not in data or 'provider_code' not in data: raise ValueError("Missing 'services' key.")
            self._log("Report parsed successfully.", 'SUCCESS')
            return data
        except Exception as e:
            self._log(f"Failed to parse report: {e}", 'ERROR')
            sys.exit(1)

    def _create_plextrac_finding(self, service, f_id, f_data, assets, description_details):
        """Builds and filters a single PlexTrac finding dictionary."""
        plextrac_severity = self.SEVERITY_MAPPING.get(f_data.get('level', ''), 'Informational')

        if self.min_severity and self.SEVERITY_RANK.get(plextrac_severity, 0) < self.SEVERITY_RANK.get(self.min_severity, 0):
            return None

        description = self._strip_html(f_data.get('description', ''))
        rationale = self._strip_html(f_data.get('rationale', ''))
        full_description = f"{description}\n\n**Rationale:**\n{rationale if rationale else 'Not provided.'}"
        full_description += "\n\n---\n\n**Affected Resource Details:**\n" + description_details

        title = ' '.join(word.capitalize() for word in f_id.replace('-', ' ').split())
        title = f"{service.upper()}: {title}"
        
        return {
            'title': title, 'severity': plextrac_severity, 'status': 'Open',
            'description': full_description,
            'recommendations': self._strip_html(f_data.get('remediation', 'N/A')),
            'references': ', '.join(f_data.get('references') or []),
            'affected_assets': ', '.join(sorted(assets)),
            'tags': ', '.join([service, 'scout-suite', f_data.get('provider_code', 'cloud')]),
            'cvss_temporal': '', 'cwe': '', 'cve': '',
            'category': service.capitalize()
        }

    def process_findings(self, scout_data):
        """Main loop to extract, filter, and format findings."""
        self._log("Processing findings...")
        plextrac_findings = []
        raw_finding_count = 0

        for service, s_data in scout_data.get('services', {}).items():
            if not isinstance(s_data, dict): continue
            for f_id, f_data in s_data.get('findings', {}).items():
                if not isinstance(f_data, dict) or f_data.get('flagged_items', 0) == 0:
                    continue
                raw_finding_count += 1

                all_assets = [self._get_asset_details(scout_data, path) for path in f_data.get('items', [])]
                
                filtered_assets = [a for a in all_assets if not self.regions_filter or a[1] in self.regions_filter]
                if not filtered_assets: continue

                if self.explode_findings:
                    for asset_id, region, details in filtered_assets:
                        finding = self._create_plextrac_finding(service, f_id, f_data, {asset_id}, details)
                        if finding: plextrac_findings.append(finding)
                else:
                    asset_ids = {a[0] for a in filtered_assets}
                    description_details = "\n\n".join(f"**Resource:** `{a[0]}`\n{a[2]}" for a in filtered_assets if a[2])
                    finding = self._create_plextrac_finding(service, f_id, f_data, asset_ids, description_details)
                    if finding: plextrac_findings.append(finding)
        
        self._log(f"Found {raw_finding_count} rules with flagged items.")
        self._log(f"Processed {len(plextrac_findings)} findings after filtering.", 'SUCCESS')
        return plextrac_findings

    def write_csv(self, findings):
        """Writes findings to a PlexTrac-compliant CSV file."""
        if not findings:
            self._log("No findings matched criteria. No CSV will be generated.", 'WARN')
            return
        self._log(f"Writing {len(findings)} findings to {self.output_file}...")
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.plextrac_headers, quoting=csv.QUOTE_ALL)
                writer.writeheader()
                writer.writerows(findings)
            self._log("CSV file written successfully.", 'SUCCESS')
        except Exception as e:
            self._log(f"Failed to write CSV file: {e}", 'ERROR')
            sys.exit(1)

    def print_summary(self, findings):
        """Prints a final summary of generated findings by severity."""
        if not findings: return
        print("\n--- Findings Breakdown ---")
        counts = {}
        for finding in findings:
            counts[finding['severity']] = counts.get(finding['severity'], 0) + 1
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if counts.get(severity, 0) > 0:
                print(f"  {severity.ljust(15)}: {counts[severity]}")
        print("------------------------")

    def run(self):
        """Orchestrates the entire conversion process."""
        print(f"\n{Colors.BOLD}--- Scout Suite to PlexTrac Converter v2.2.2 ---{Colors.ENDC}")
        self._log(f"Input File:           {self.input_file}")
        self._log(f"Output File:          {self.output_file}")
        self._log(f"Minimum Severity:     {self.min_severity or 'All'}")
        self._log(f"Regions:              {', '.join(self.regions_filter) or 'All'}")
        self._log(f"Consolidate Findings: {not self.explode_findings}")
        print("-" * 46)

        scout_data = self.parse_report()
        findings = self.process_findings(scout_data)
        self.print_summary(findings)
        self.write_csv(findings)
        self._log(f"\nConversion complete! Upload '{self.output_file}' to PlexTrac.", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(
        description='A production-ready tool to convert Scout Suite JSON reports into PlexTrac-compliant CSV files.',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Usage Examples:
  # Basic conversion (consolidates findings, accurate assets, rich descriptions)
  python %(prog)s scoutsuite_results_aws.js

  # Filter for high/critical findings in us-east-1
  python %(prog)s report.js -o critical.csv --min-severity High --regions us-east-1
"""
    )
    parser.add_argument('input_file', help='Path to the source Scout Suite report file (JSON/JS format).')
    parser.add_argument('-o', '--output', dest='output_file', help='Output CSV file path. Defaults to "<input_file>_plextrac.csv".')
    
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument('--min-severity', choices=['Critical', 'High', 'Medium', 'Low', 'Informational'], help='Filter to include findings of this severity or higher.')
    filter_group.add_argument('--regions', type=lambda s: [item.strip() for item in s.split(',')], help='Comma-separated list of cloud regions to include (e.g., "us-east-1,eu-west-2").')
    
    format_group = parser.add_argument_group('Output Formatting Options')
    format_group.add_argument('--explode-findings', action='store_true', help='Disables consolidation. Creates a separate finding for each affected asset.')
    
    args = parser.parse_args()
    
    options = {
        'min_severity': args.min_severity,
        'regions': args.regions,
        'explode_findings': args.explode_findings,
    }

    ScoutSuiteToPlexTrac(args.input_file, args.output_file, **options).run()


if __name__ == '__main__':
    main()
