# scout2plexExporter


# Scout Suite to PlexTrac Converter

A powerful Python script to convert JSON reports from **Scout Suite** into a feature-rich, import-ready CSV format for **PlexTrac**.

This tool goes beyond simple conversion, offering advanced filtering, intelligent finding consolidation, and evidence extraction to streamline your cloud security assessment workflow. It is designed to be used in a production environment to quickly and easily process security findings.

---

## Key Features

* **Advanced Filtering**: Narrow down reports to what matters most by filtering findings on **minimum severity** and specific **cloud regions**.
* **Intelligent Deduplication**: Automatically consolidates all assets affected by a single rule into one PlexTrac finding, drastically reducing noise.
* **"Explode" Findings Option**: Disable consolidation to create a separate finding for each affected asset, allowing for granular tracking.
* **Evidence Extraction**: Automatically extracts the JSON configuration of a misconfigured resource and adds it to a `code_sample` field for immediate context.
* **Robust & Verbose**: Built with clear error handling and informational logging to make operation smooth and transparent.
* **Native Format Handling**: Correctly parses Scout Suite's JavaScript output format (`scoutsuite_results = {...}`).

---

## Prerequisites

* Python 3.6+
* A Scout Suite JSON/JS report file.

---

## Usage

The script is run from the command line, with the Scout Suite report as the main input.

```bash
python scout_to_plextrac.py <path_to_scout_suite_report.js> [OPTIONS]
```

### Command-Line Arguments

| Argument                | Alias | Description                                                                                             |
| ----------------------- | ----- | ------------------------------------------------------------------------------------------------------- |
| `input_file`            |       | (Required) The path to the source Scout Suite report file.                                              |
| `--output`              | `-o`  | The path for the generated CSV file. Defaults to the same name as the input file with a `.csv` extension. |
| `--min-severity`        |       | Filter findings to this severity or higher. Choices: `Critical`, `High`, `Medium`, `Low`, `Informational`. |
| `--regions`             |       | A comma-separated list of cloud regions to include (e.g., `us-east-1,eu-west-1`).                       |
| `--explode-findings`    |       | Disables consolidation and creates a separate finding for each affected asset.                          |
| `--include-evidence`    |       | Extracts the resource's JSON configuration into a `code_sample` custom field in the CSV.                |

### Examples

**1. Basic Conversion**
Convert a report with default settings (consolidated findings, all severities, all regions).

```bash
python scout_to_plextrac.py scoutsuite_results_aws-123456789.js
```

**2. Filtered Report for a Specific Team**
Create a report for the `us-east-1` team containing only `High` and `Critical` findings, and include the JSON evidence for each.

```bash
python scout_to_plextrac.py report.js -o us-east-1_critical.csv \
    --min-severity High \
    --regions us-east-1 \
    --include-evidence
```

**3. Granular Tracking**
Create a highly detailed report where every single affected asset gets its own line item in the CSV. This is useful for workflows that require tracking remediation on a per-asset basis.

```bash
python scout_to_plextrac.py report.js --explode-findings
```

-----

## Advanced Features

### Deduplication Strategy

By default, the tool consolidates findings to reduce duplication. For example, if Scout Suite finds 15 S3 buckets with logging disabled, the tool generates **one** PlexTrac finding titled "S3: Bucket No Logging" and lists all 15 bucket names in the `affected_assets` field.

Using the `--explode-findings` flag disables this behavior and would instead generate 15 separate findings in the CSV, one for each bucket.

### Evidence Extraction

When you use the `--include-evidence` flag, the script adds a `code_sample` column to the output CSV. This column will be populated with the full JSON object of the affected resource, as captured in the Scout Suite report.

**❗ Important PlexTrac Setup:**
For this feature to work upon import, you must first create a **Custom Field** in your PlexTrac instance.

  * **Field Name:** `code_sample`
  * **Field Type:** `Code Sample`

When you import the CSV, PlexTrac will automatically map the evidence from this column into the "Code Sample / Screenshot" section of the finding.

-----

## Importing to PlexTrac

1.  Log in to your PlexTrac instance.
2.  Navigate to the desired Client and Report.
3.  Click **Add Findings** and select **Import from File**.
4.  Upload the generated CSV file.
5.  Map the columns if necessary (they should map automatically) and complete the import.

<!-- end list -->
