package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"testing"
)

// mockSBOM creates a mock SBOM for testing purposes.
func mockSBOM() *SBOM {
	return &SBOM{
		Modules: []ModuleInfo{
			{
				Name:    "aws_vpc",
				Source:  "git::https://github.com/terraform-aws-modules/vpc.git?ref=v2.0.0",
				Version: "v2.0.0",
				Config:  "/path/to/config",
			},
			{
				Name:    "s3_bucket",
				Source:  "hashicorp/aws",
				Version: "N/A",
				Config:  "/path/to/config",
			},
		},
	}
}

// TestWriteSBOMToCSV tests CSV output functionality.
func TestWriteSBOMToCSV(t *testing.T) {
	sbom := mockSBOM()

	tmpFile, err := os.CreateTemp("", "test_output.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name()) // clean up

	err = writeSBOMToCSV(sbom, tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to write SBOM to CSV: %v", err)
	}

	// Read and validate the CSV content
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV records: %v", err)
	}

	// Expected CSV header and records
	expected := [][]string{
		{"/path/to/config", "aws_vpc", "git::https://github.com/terraform-aws-modules/vpc.git?ref=v2.0.0", "v2.0.0"},
		{"/path/to/config", "s3_bucket", "hashicorp/aws", "N/A"},
	}

	for i, record := range records {
		for j, field := range record {
			if field != expected[i][j] {
				t.Errorf("CSV content mismatch: expected %v, got %v", expected[i][j], field)
			}
		}
	}
}

// TestWriteSBOMToJSON tests JSON output functionality.
func TestWriteSBOMToJSON(t *testing.T) {
	sbom := mockSBOM()

	tmpFile, err := os.CreateTemp("", "test_output.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name()) // clean up

	err = writeSBOMToJSON(sbom, tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to write SBOM to JSON: %v", err)
	}

	// Read and validate the JSON content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read JSON file: %v", err)
	}

	var result SBOM
	err = json.Unmarshal(content, &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON content: %v", err)
	}

	// Compare the result with the original SBOM
	if len(result.Modules) != len(sbom.Modules) {
		t.Fatalf("JSON output mismatch: expected %d modules, got %d", len(sbom.Modules), len(result.Modules))
	}

	for i, mod := range result.Modules {
		if mod != sbom.Modules[i] {
			t.Errorf("JSON content mismatch: expected %v, got %v", sbom.Modules[i], mod)
		}
	}
}

// TestWriteSBOMToXML tests XML output functionality.
func TestWriteSBOMToXML(t *testing.T) {
	sbom := mockSBOM()

	tmpFile, err := os.CreateTemp("", "test_output.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name()) // clean up

	err = writeSBOMToXML(sbom, tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to write SBOM to XML: %v", err)
	}

	// Read and validate the XML content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read XML file: %v", err)
	}

	var result SBOM
	err = xml.Unmarshal(content, &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal XML content: %v", err)
	}

	// Compare the result with the original SBOM
	if len(result.Modules) != len(sbom.Modules) {
		t.Fatalf("XML output mismatch: expected %d modules, got %d", len(sbom.Modules), len(result.Modules))
	}

	for i, mod := range result.Modules {
		if mod != sbom.Modules[i] {
			t.Errorf("XML content mismatch: expected %v, got %v", sbom.Modules[i], mod)
		}
	}
}
