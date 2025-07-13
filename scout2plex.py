#!/usr/bin/env python3
"""
Scout Suite to PlexTrac Converter (v2.1)

A production-ready tool to convert Scout Suite JSON report output into a 
feature-rich, PlexTrac-compliant CSV format. This enhanced version includes 
advanced filtering, finding deduplication, and evidence extraction capabilities.
"""

import json
import csv
import argparse
import os
import sys
import re
from pathlib import Path

art = '''
     _______.  ______   ______    __    __  .___________.___   .______    __       __________   ___ 
    /       | /      | /  __  \  |  |  |  | |           |__ \  |   _  \  |  |     |   ____\  \ /  / 
   |   (----`|  ,----'|  |  |  | |  |  |  | `---|  |----`  ) | |  |_)  | |  |     |  |__   \  V  /  
    \   \    |  |     |  |  |  | |  |  |  |     |  |      / /  |   ___/  |  |     |   __|   >   <   
.----)   |   |  `----.|  `--'  | |  `--'  |     |  |     / /_  |  |      |  `----.|  |____ /  .  \  
|_______/     \______| \______/   \______/      |__|    |____| | _|      |_______||_______/__/ \__\ 
                                                                                                    
'''
print(art)

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
        'Critical': 5,
        'High': 4,
        'Medium': 3,
        'Low': 2,
        'Informational': 1
    }

    def __init__(self, input_file, output_file=None, **kwargs):
        """Initializes the converter with files and processing options."""
        self.input_file = Path(input_file)
        if output_file:
            self.output_file = Path(output_file)
        else:
            self.output_file = self.input_file.with_name(f"{self.input_file.stem}_plextrac.csv")

        # Processing options from argparse
        self.min_severity = kwargs.get('min_severity')
        self.regions_filter = kwargs.get('regions', [])
        self.explode_findings = kwargs.get('explode_findings', False)
        self.include_evidence = kwargs.get('include_evidence', False)

        # Dynamically set headers
        self.plextrac_headers = [
            'title', 'severity', 'status', 'description', 'recommendations',
            'references', 'affected_assets', 'tags', 'cvss_temporal',
            'cwe', 'cve', 'category'
        ]
        if self.include_evidence:
            self.plextrac_headers.append('code_sample')

    # --- Logging and Utility Methods ---
    def _log(self, message, level='INFO'):
        """Prints a formatted log message."""
        color_map = {'INFO': Colors.BLUE, 'SUCCESS': Colors.GREEN, 'WARN': Colors.YELLOW, 'ERROR': Colors.RED}
        print(f"{color_map.get(level, Colors.BLUE)}[{level.ljust(7)}] {Colors.ENDC}{message}")

    def _strip_html(self, text):
        """Removes common HTML tags from a string for cleaner output."""
        if not text:
            return ""
        return re.sub('<[^<]+?>', '', text).strip()

    def _resolve_path(self, data, path_str):
        """Resolves a dot-separated path string within a nested dictionary."""
        try:
            value = data
            for key in path_str.split('.'):
                if isinstance(value, dict) and key in value:
                    value = value[key]
                elif isinstance(value, list) and key.isdigit():
                    value = value[int(key)]
                else:
                    return None
            return value
        except (KeyError, IndexError, TypeError):
            return None

    def _get_asset_details(self, item_path):
        """Extracts an asset's name and region from its item path string."""
        region_match = re.search(r'\.regions\.([\w-]+)\.', item_path)
        region = region_match.group(1) if region_match else 'global'
        
        asset_name = item_path.split('.')[-1]
        if asset_name in self.SEVERITY_MAPPING or asset_name.lower() in ["true", "false"]:
             asset_name = item_path.split('.')[-2]

        return asset_name, region

    # --- Core Processing Methods ---
    def parse_report(self):
        """Parses the Scout Suite report, handling the JS variable format."""
        self._log(f"Reading report: {self.input_file}")
        try:
            content = self.input_file.read_text(encoding='utf-8')
            if not content:
                raise ValueError("Input file is empty.")

            json_content = content.split('=', 1)[1].strip() if content.strip().startswith('scoutsuite_results') else content
            data = json.loads(json_content)

            if 'services' not in data or 'provider_code' not in data:
                raise ValueError("File is missing 'services' or 'provider_code' keys.")
            
            self._log("Report parsed successfully.", 'SUCCESS')
            return data
        except FileNotFoundError:
            self._log(f"Input file not found: {self.input_file}", 'ERROR')
        except (json.JSONDecodeError, ValueError) as e:
            self._log(f"Invalid Scout Suite report file: {e}", 'ERROR')
        except Exception as e:
            self._log(f"An unexpected error occurred while reading the file: {e}", 'ERROR')
        sys.exit(1)

    def _format_plextrac_finding(self, service, f_id, f_data, assets, evidence=""):
        """Formats and filters a single finding before it's added to the final list."""
        plextrac_severity = self.SEVERITY_MAPPING.get(f_data.get('level', ''), 'Informational')
        
        # Severity Filter
        if self.min_severity and self.SEVERITY_RANK.get(plextrac_severity, 0) < self.SEVERITY_RANK.get(self.min_severity, 0):
            return None
        
        # Prepare fields
        title = ' '.join(word.capitalize() for word in f_id.replace('-', ' ').split())
        title = f"{service.upper()}: {title}"
        if self.explode_findings and len(assets) == 1:
             title += f" in {assets[0]}"
        
        description = self._strip_html(f_data.get('description', ''))
        rationale = self._strip_html(f_data.get('rationale', ''))
        full_description = f"{description}\n\n**Rationale:**\n{rationale}" if rationale else description
        
        tags = [service, 'scout-suite', f_data.get('provider_code', 'cloud')]

        finding = {
            'title': title, 'severity': plextrac_severity, 'status': 'Open',
            'description': full_description,
            'recommendations': self._strip_html(f_data.get('remediation', 'N/A')),
            'references': ', '.join(f_data.get('references', [])),
            'affected_assets': ', '.join(sorted(assets)),
            'tags': ', '.join(tags),
            'cvss_temporal': '', 'cwe': '', 'cve': '',
            'category': service.capitalize()
        }
        if self.include_evidence:
            finding['code_sample'] = evidence
        return finding

    def process_findings(self, scout_data):
        """Extracts, filters, and processes findings based on runtime options."""
        self._log("Processing findings...")
        plextrac_findings = []
        raw_finding_count = 0

        for service, service_data in scout_data.get('services', {}).items():
            for finding_id, f_data in service_data.get('findings', {}).items():
                if f_data.get('flagged_items', 0) == 0:
                    continue
                raw_finding_count += 1
                
                all_assets = {path: self._get_asset_details(path) for path in f_data.get('items', [])}
                
                # Apply region filtering to the assets of this finding
                filtered_assets = {
                    path: details for path, details in all_assets.items()
                    if not self.regions_filter or details[1] in self.regions_filter
                }

                if not filtered_assets:
                    continue

                # Branch logic based on consolidation vs. exploding
                if self.explode_findings:
                    for path, (name, region) in filtered_assets.items():
                        evidence = json.dumps(self._resolve_path(scout_data, path), indent=2) if self.include_evidence else ""
                        finding = self._format_plextrac_finding(service, finding_id, f_data, [name], evidence)
                        if finding:
                            plextrac_findings.append(finding)
                else:
                    asset_names = {details[0] for details in filtered_assets.values()}
                    evidence = ""
                    if self.include_evidence:
                        evidence_list = [json.dumps(self._resolve_path(scout_data, path), indent=2) for path in filtered_assets]
                        evidence = "\n\n---\n\n".join(evidence_list)
                    
                    finding = self._format_plextrac_finding(service, finding_id, f_data, asset_names, evidence)
                    if finding:
                        plextrac_findings.append(finding)
        
        self._log(f"Found {raw_finding_count} rules with flagged items.")
        self._log(f"Processed {len(plextrac_findings)} findings after filtering.", 'SUCCESS')
        return plextrac_findings

    def write_csv(self, findings):
        """Writes the list of findings to a PlexTrac-compliant CSV file."""
        if not findings:
            self._log("No findings matched the criteria. No CSV will be generated.", 'WARN')
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

    def print_summary(self, findings):
        """Prints a final summary of the generated findings by severity."""
        if not findings:
            return
        
        print("\n--- Findings Breakdown ---")
        counts = {}
        for finding in findings:
            severity = finding['severity']
            counts[severity] = counts.get(severity, 0) + 1
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if counts.get(severity, 0) > 0:
                print(f"  {severity.ljust(15)}: {counts[severity]}")
        print("------------------------")

    def run(self):
        """Main conversion process."""
        print(f"\n{Colors.BOLD}--- Scout Suite to PlexTrac Converter v2.1 ---{Colors.ENDC}")
        self._log(f"Input File:           {self.input_file}")
        self._log(f"Output File:          {self.output_file}")
        self._log(f"Minimum Severity:     {self.min_severity or 'All'}")
        self._log(f"Regions:              {', '.join(self.regions_filter) or 'All'}")
        self._log(f"Consolidate Findings: {not self.explode_findings}")
        self._log(f"Include Evidence:     {self.include_evidence}")
        print("-" * 44)

        scout_data = self.parse_report()
        findings = self.process_findings(scout_data)
        self.print_summary(findings)
        self.write_csv(findings)
        
        self._log(f"\nConversion complete! Upload '{self.output_file}' to PlexTrac.", "SUCCESS")
        
def main():
    """Main function to handle command-line arguments and run the converter."""
    parser = argparse.ArgumentParser(
        description='A production-ready tool to convert Scout Suite JSON reports into PlexTrac-compliant CSV files.',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Usage Examples:
  
  # Basic conversion (consolidates findings by default)
  python %(prog)s scoutsuite_results_aws.js

  # Filter for high/critical findings in us-east-1 and include JSON evidence
  python %(prog)s report.js -o critical.csv --min-severity High --regions us-east-1 --include-evidence
  
  # Create a separate finding for each affected asset (no consolidation)
  python %(prog)s report.js --explode-findings
"""
    )
    
    parser.add_argument('input_file', help='Path to the source Scout Suite report file (JSON/JS format).')
    parser.add_argument('-o', '--output', dest='output_file', help='Output CSV file path. Defaults to "<input_file>_plextrac.csv".')
    
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument('--min-severity', choices=['Critical', 'High', 'Medium', 'Low', 'Informational'],
                              help='Filter to include findings of this severity or higher.')
    filter_group.add_argument('--regions', type=lambda s: [item.strip() for item in s.split(',')],
                              help='Comma-separated list of cloud regions to include (e.g., "us-east-1,eu-west-2").')

    format_group = parser.add_argument_group('Output Formatting Options')
    format_group.add_argument('--explode-findings', action='store_true',
                              help='Disables consolidation. Creates a separate finding for each affected asset.')
    format_group.add_argument('--include-evidence', action='store_true',
                              help='Extracts resource JSON as evidence into a "code_sample" custom field.')

    args = parser.parse_args()
    
    options = {
        'min_severity': args.min_severity,
        'regions': args.regions,
        'explode_findings': args.explode_findings,
        'include_evidence': args.include_evidence
    }

    ScoutSuiteToPlexTrac(args.input_file, args.output_file, **options).run()


if __name__ == '__main__':
    main()
