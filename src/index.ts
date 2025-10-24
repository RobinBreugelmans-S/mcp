import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// OSV API base URL for vulnerability checking
const OSV_API_BASE = "https://api.osv.dev/v1";

// Create server instance
const server = new McpServer({
  name: "CVE Checker MCP",
  version: "1.0.0",
  capabilities: {
    resources: {},
    tools: {},
  },
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Weather MCP Server running on stdio");
}

interface AlertFeature {
  properties: {
    event?: string;
    areaDesc?: string;
    severity?: string;
    status?: string;
    headline?: string;
  };
}

// Format alert data
function formatAlert(feature: AlertFeature): string {
  const props = feature.properties;
  return [
    `Event: ${props.event || "Unknown"}`,
    `Area: ${props.areaDesc || "Unknown"}`,
    `Severity: ${props.severity || "Unknown"}`,
    `Status: ${props.status || "Unknown"}`,
    `Headline: ${props.headline || "No headline"}`,
    "---",
  ].join("\n");
}

interface ForecastPeriod {
  name?: string;
  temperature?: number;
  temperatureUnit?: string;
  windSpeed?: string;
  windDirection?: string;
  shortForecast?: string;
}

interface AlertsResponse {
  features: AlertFeature[];
}

interface PointsResponse {
  properties: {
    forecast?: string;
  };
}

interface ForecastResponse {
  properties: {
    periods: ForecastPeriod[];
  };
}

// CVE/Vulnerability interfaces
interface VulnerabilityResponse {
  vulns?: Vulnerability[];
}

interface Vulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Severity[];
  database_specific?: {
    severity?: string;
  };
  modified?: string;
  published?: string;
  references?: Reference[];
  affected?: Affected[];
}

interface Severity {
  type: string;
  score: string;
}

interface Reference {
  type: string;
  url: string;
}

interface Affected {
  package?: {
    name?: string;
    ecosystem?: string;
  };
  ranges?: Array<{
    type: string;
    events: Array<{ introduced?: string; fixed?: string }>;
  }>;
  versions?: string[];
}

// Helper function to check CVEs for a package
async function checkPackageVulnerabilities(
  packageName: string,
  version?: string
): Promise<{ vulnerabilities: Vulnerability[]; hasVulnerabilities: boolean }> {
  const queryUrl = `${OSV_API_BASE}/query`;
  
  const payload = {
    package: {
      name: packageName,
      ecosystem: "npm",
    },
    ...(version && { version }),
  };

  try {
    const response = await fetch(queryUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = (await response.json()) as VulnerabilityResponse;
    const vulnerabilities = data.vulns || [];
    
    return {
      vulnerabilities,
      hasVulnerabilities: vulnerabilities.length > 0,
    };
  } catch (error) {
    console.error("Error checking vulnerabilities:", error);
    throw error;
  }
}

// Format vulnerability data for display
function formatVulnerability(vuln: Vulnerability): string {
  const lines = [
    `ID: ${vuln.id}`,
    `Summary: ${vuln.summary || "No summary available"}`,
  ];

  // Add severity if available
  if (vuln.severity && vuln.severity.length > 0) {
    const severity = vuln.severity[0];
    lines.push(`Severity: ${severity.type} - ${severity.score}`);
  } else if (vuln.database_specific?.severity) {
    lines.push(`Severity: ${vuln.database_specific.severity}`);
  }

  // Add published date
  if (vuln.published) {
    lines.push(`Published: ${new Date(vuln.published).toLocaleDateString()}`);
  }

  // Add affected versions if available
  if (vuln.affected && vuln.affected.length > 0) {
    const affected = vuln.affected[0];
    if (affected.ranges && affected.ranges.length > 0) {
      const range = affected.ranges[0];
      const events = range.events || [];
      const introduced = events.find((e) => e.introduced)?.introduced;
      const fixed = events.find((e) => e.fixed)?.fixed;
      
      if (introduced) lines.push(`Introduced in: ${introduced}`);
      if (fixed) lines.push(`Fixed in: ${fixed}`);
    }
  }

  // Add references if available
  if (vuln.references && vuln.references.length > 0) {
    lines.push(`References:`);
    vuln.references.slice(0, 3).forEach((ref) => {
      lines.push(`  - ${ref.url}`);
    });
  }

  lines.push("---");
  return lines.join("\n");
}

// Register CVE checking tool
server.tool(
  "check_package_cves",
  "Check for known CVEs/vulnerabilities in npm packages before installation",
  {
    packageName: z
      .string()
      .describe("Name of the npm package to check for vulnerabilities"),
    version: z
      .string()
      .optional()
      .describe(
        "Specific version to check (optional). If not provided, checks all known vulnerabilities for the package."
      ),
  },
  async ({ packageName, version }) => {
    try {
      const result = await checkPackageVulnerabilities(packageName, version);

      if (!result.hasVulnerabilities) {
        return {
          content: [
            {
              type: "text",
              text: `✅ No known vulnerabilities found for package "${packageName}"${version ? ` version ${version}` : ""}.`,
            },
          ],
        };
      }

      const vulnCount = result.vulnerabilities.length;
      const formattedVulns = result.vulnerabilities
        .map(formatVulnerability)
        .join("\n");

      const warningText = [
        `⚠️  Found ${vulnCount} known vulnerabilit${vulnCount === 1 ? "y" : "ies"} for package "${packageName}"${version ? ` version ${version}` : ""}:`,
        "",
        formattedVulns,
        "",
        "⚠️  WARNING: Consider using a different package or version without known vulnerabilities.",
      ].join("\n");

      return {
        content: [
          {
            type: "text",
            text: warningText,
          },
        ],
        isError: false,
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error checking vulnerabilities for "${packageName}": ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Register bulk CVE checking tool for multiple packages
server.tool(
  "check_packages_bulk_cves",
  "Check multiple npm packages for CVEs at once (useful before installing dependencies)",
  {
    packages: z
      .array(
        z.object({
          name: z.string().describe("Package name"),
          version: z
            .string()
            .optional()
            .describe("Specific version (optional)"),
        })
      )
      .describe("Array of packages to check"),
  },
  async ({ packages }) => {
    try {
      const results = await Promise.all(
        packages.map(async (pkg) => {
          try {
            const result = await checkPackageVulnerabilities(
              pkg.name,
              pkg.version
            );
            return {
              package: pkg.name,
              version: pkg.version,
              hasVulnerabilities: result.hasVulnerabilities,
              vulnerabilityCount: result.vulnerabilities.length,
              vulnerabilities: result.vulnerabilities,
            };
          } catch (error) {
            return {
              package: pkg.name,
              version: pkg.version,
              hasVulnerabilities: false,
              vulnerabilityCount: 0,
              vulnerabilities: [],
              error: error instanceof Error ? error.message : String(error),
            };
          }
        })
      );

      const packagesWithVulns = results.filter((r) => r.hasVulnerabilities);
      const totalVulns = results.reduce(
        (sum, r) => sum + r.vulnerabilityCount,
        0
      );

      let responseText = `📦 Checked ${packages.length} package(s) for vulnerabilities:\n\n`;

      if (packagesWithVulns.length === 0) {
        responseText += `✅ No known vulnerabilities found in any of the packages!`;
      } else {
        responseText += `⚠️  Found vulnerabilities in ${packagesWithVulns.length} package(s) (${totalVulns} total vulnerabilities):\n\n`;

        for (const result of packagesWithVulns) {
          responseText += `\n📦 Package: ${result.package}${result.version ? ` (v${result.version})` : ""}\n`;
          responseText += `   Vulnerabilities: ${result.vulnerabilityCount}\n\n`;
          
          result.vulnerabilities.forEach((vuln) => {
            responseText += formatVulnerability(vuln) + "\n";
          });
        }

        responseText += `\n⚠️  WARNING: Consider reviewing these vulnerabilities before installation.`;
      }

      // Add summary of packages checked
      responseText += `\n\n📊 Summary:\n`;
      results.forEach((r) => {
        const status = r.hasVulnerabilities ? "⚠️ " : "✅";
        const vulnInfo = r.hasVulnerabilities
          ? ` (${r.vulnerabilityCount} vulnerabilities)`
          : "";
        responseText += `${status} ${r.package}${r.version ? `@${r.version}` : ""}${vulnInfo}\n`;
      });

      return {
        content: [
          {
            type: "text",
            text: responseText,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error checking vulnerabilities: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

main().catch((error) => {
  console.error("Fatal error in main(): ", error);
  process.exit(1);
});