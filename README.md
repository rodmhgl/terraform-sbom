# Terraform SBOM

This repository contains a Terraform module for generating a Software Bill of Materials (SBOM) for your infrastructure as code.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Contributing](#contributing)
- [License](#license)

## Introduction

The Terraform SBOM module helps you create a detailed inventory of all the software components used in your Terraform-managed infrastructure. This can be useful for compliance, security audits, and maintaining an up-to-date inventory of your software assets.

## Features

- Automatically generate SBOM for Terraform-managed resources

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 0.12
- [Go](https://golang.org/dl/) (for building the SBOM generator)

## Usage

```shell
go run main.go /path/to/terraform/config output.csv
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.