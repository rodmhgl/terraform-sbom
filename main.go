package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
)

// ModuleInfo represents the information about a Terraform module.
// It includes the module's name, source, version, and configuration.
type ModuleInfo struct {
	Name    string `json:"name" xml:"Name"`
	Source  string `json:"source" xml:"Source"`
	Version string `json:"version" xml:"Version"`
	Config  string `json:"config" xml:"ConfigPath"`
}

// SBOM represents a Software Bill of Materials (SBOM) which contains a list of modules.
// It is used to track the components and dependencies of the Terraform config.
type SBOM struct {
	XMLName xml.Name     `json:"-" xml:"SBOM"` // Root element in the XML
	Modules []ModuleInfo `json:"modules" xml:"Modules>Module"`
}

// generateSBOM generates a Software Bill of Materials (SBOM) for a given Terraform configuration.
// It loads the Terraform module from the specified configuration path, extracts module information,
// and constructs an SBOM containing details about each module call.
func generateSBOM(configPath string) (*SBOM, error) {
	module, diag := tfconfig.LoadModule(configPath)
	if diag.HasErrors() {
		return nil, fmt.Errorf("failed to load Terraform module: %v", diag.Err())
	}

	var sbom SBOM

	for _, modCall := range module.ModuleCalls {
		modInfo := ModuleInfo{
			Name:   modCall.Name,
			Source: modCall.Source,
			Config: configPath, // Store the config path in the module info
		}

		// Try to extract version from the module source or version field
		modInfo.Version = extractVersion(modCall)

		sbom.Modules = append(sbom.Modules, modInfo)
	}

	return &sbom, nil
}

// extractVersion extracts the version of a Terraform module from a given ModuleCall.
func extractVersion(modCall *tfconfig.ModuleCall) string {
	if modCall.Version != "" {
		return modCall.Version
	}

	source := modCall.Source
	if strings.Contains(source, "?ref=") {
		parts := strings.Split(source, "?ref=")
		if len(parts) > 1 {
			return parts[1]
		}
	}

	if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
		return "local"
	}

	return "N/A"
}

// printSBOM prints the Software Bill of Materials (SBOM) for a given Terraform configuration.
// It outputs the configuration path, module name, source, and version for each module in the SBOM.
func printSBOM(sbom *SBOM) {
	fmt.Println("Software Bill of Materials (SBOM) for Terraform configuration")
	fmt.Println("-----------------------------------------------------------")
	for _, mod := range sbom.Modules {
		fmt.Printf("Config Path: %s\n", mod.Config)
		fmt.Printf("Module Name: %s\n", mod.Name)
		fmt.Printf("Source: %s\n", mod.Source)
		fmt.Printf("Version: %s\n\n", mod.Version)
	}
}

// writeSBOMToCSV writes the Software Bill of Materials (SBOM) to a CSV file.
// If the file does not exist, it creates a new one and writes the header.
// If the file exists, it appends the SBOM data to the file.
func writeSBOMToCSV(sbom *SBOM, outputPath string) error {
	fileExists := fileExists(outputPath)

	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if !fileExists {
		err = writer.Write([]string{"Config Path", "Module Name", "Source", "Version"})
		if err != nil {
			return fmt.Errorf("failed to write CSV header: %v", err)
		}
	}

	for _, mod := range sbom.Modules {
		err = writer.Write([]string{mod.Config, mod.Name, mod.Source, mod.Version})
		if err != nil {
			return fmt.Errorf("failed to write CSV record: %v", err)
		}
	}

	fmt.Printf("SBOM successfully written to %s\n", outputPath)
	return nil
}

// writeSBOMToJSON writes the SBOM to a JSON file
func writeSBOMToJSON(sbom *SBOM, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Pretty print the JSON

	err = encoder.Encode(sbom)
	if err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	fmt.Printf("SBOM successfully written to %s\n", outputPath)
	return nil
}

// writeSBOMToXML writes the SBOM to an XML file
func writeSBOMToXML(sbom *SBOM, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create XML file: %v", err)
	}
	defer file.Close()

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ") // Pretty print the XML

	err = encoder.Encode(sbom)
	if err != nil {
		return fmt.Errorf("failed to write XML file: %v", err)
	}

	fmt.Printf("SBOM successfully written to %s\n", outputPath)
	return nil
}

// fileExists checks if a file exists at the given file path.
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	outputFormat := flag.String("output", "csv", "Specify output format: csv, json, or xml. Defaults to csv")
	flag.Parse()

	if flag.NArg() < 2 {
		log.Fatalf("Usage: %s <path-to-terraform-config> <output-file>", filepath.Base(os.Args[0]))
	}

	configPath := flag.Arg(0)
	outputPath := flag.Arg(1)

	sbom, err := generateSBOM(configPath)
	if err != nil {
		log.Fatalf("Error generating SBOM: %v", err)
	}

	if *verbose {
		printSBOM(sbom)
	}

	switch strings.ToLower(*outputFormat) {
	case "csv":
		err = writeSBOMToCSV(sbom, outputPath)
	case "json":
		err = writeSBOMToJSON(sbom, outputPath)
	case "xml":
		err = writeSBOMToXML(sbom, outputPath)
	default:
		log.Fatalf("Unsupported output format: %s. Supported formats are: csv, json, xml", *outputFormat)
	}

	if err != nil {
		log.Fatalf("Error writing SBOM: %v", err)
	}
}
