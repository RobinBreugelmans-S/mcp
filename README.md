# MCP Server with CVE Checker for Node Modules

This Model Context Protocol (MCP) server provides tools for checking Common Vulnerabilities and Exposures (CVEs) in npm packages before installation, along with weather information tools.

## Features

### CVE Checking Tools

- **check_package_cves**: Check a single npm package for known vulnerabilities
- **check_packages_bulk_cves**: Check multiple npm packages at once before installation

## CVE Checking

The server uses the [OSV (Open Source Vulnerabilities) API](https://osv.dev/) to check npm packages for known security vulnerabilities. This helps you make informed decisions before installing packages.

### Usage Examples

#### Check a single package:

```json
{
	"tool": "check_package_cves",
	"arguments": {
		"packageName": "express",
		"version": "4.17.1"
	}
}
```

#### Check multiple packages at once:

```json
{
	"tool": "check_packages_bulk_cves",
	"arguments": {
		"packages": [
			{ "name": "express", "version": "4.17.1" },
			{ "name": "lodash", "version": "4.17.20" },
			{ "name": "axios" }
		]
	}
}
```

## Building and Running

1. Install dependencies:

```bash
npm install
```

2. Build the project:

```bash
npm run build
```

3. Run the MCP server:

```bash
node build/index.js
```

## Integration

This MCP server can be integrated with any MCP-compatible client to provide CVE checking capabilities before installing npm packages.
