/**
 * API service for fetching VAPT report data from the backend
 */

export interface Metadata {
  title: string;
  author: string;
  subject: string;
  keywords: string;
  creator: string;
  producer: string;
  page_count: number;
  file_size: number;
  assessment_date: string;
  test_type: string;
}

export interface Finding {
  title: string;
  description: string;
  severity: string;
  impact: string;
  remediation: string;
  affected_url?: string;
  reference?: string;
  cvss_score?: {
    base: number;
    temporal: number;
    environmental: number;
  };
  proof_of_concept?: {
    steps: Array<{
      title: string;
      description: string;
      command?: string;
      response?: string;
      findings?: string[];
    }>;
    key_issues?: string[];
    summary?: string[];
  };
}

export interface ReportContent {
  title: string;
  executive_summary: string;
  findings: Finding[];
  methodology: string;
  recommendations: string[];
  conclusion: string;
}

export interface ReportData {
  metadata: Metadata;
  content: ReportContent;
}

const API_URL = 'http://localhost:8000/api';

/**
 * Fetch the full VAPT report data
 */
export async function fetchReport(): Promise<ReportData> {
  try {
    const response = await fetch(`${API_URL}/report`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching report:', error);
    throw error;
  }
}

/**
 * Fetch only the metadata of the VAPT report
 */
export async function fetchMetadata(): Promise<Metadata> {
  try {
    const response = await fetch(`${API_URL}/report/metadata`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    const data = await response.json();
    return data.metadata;
  } catch (error) {
    console.error('Error fetching metadata:', error);
    throw error;
  }
}

/**
 * Fetch only the content of the VAPT report
 */
export async function fetchContent(): Promise<ReportContent> {
  try {
    const response = await fetch(`${API_URL}/report/content`);
    
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    
    const data = await response.json();
    return data.content;
  } catch (error) {
    console.error('Error fetching content:', error);
    throw error;
  }
}

export const mockFindings: Finding[] = [
  {
    title: "Unauthenticated Access to Hub (SignalR)",
    severity: "Medium",
    description: `SignalR can be used with ASP.NET Core authentication to associate a user with each connection. In a hub, authentication data can be accessed from the HubConnectionContext.User property. Authentication allows the hub to call methods on all connections associated with a user. For more information, see Manage users and groups in SignalR. Multiple connections may be associated with a single user.`,
    impact: `• Moderate risk due to data exposure in a customer-facing system.
• Potential compliance issues if sensitive information is leaked.
• Reputation damage if customers receive spoofed messages.`,
    remediation: `• Implement authentication on SignalR hubs.
• Secure token handling (short expiration, move to headers).
• Restrict transport methods to WebSockets.
• Disable detailed error messages.
• Sanitize input to prevent XSS.`,
    affected_url: "https://staging-customerportal.more.com.au/signalr",
    reference: "https://learn.microsoft.com/en-us/aspnet/core/signalr/authn-and-authz?view=aspnetcore-9.0",
    cvss_score: {
      base: 5.4,
      temporal: 4.9,
      environmental: 6.1
    },
    proof_of_concept: {
      steps: [
        {
          title: "Initial Investigation",
          description: "Determine if an unauthenticated connection to the SignalR hub (messagesHub) is possible.",
          command: 'curl -s "https://staging-customerportal.more.com.au/signalr/negotiate?connectionData=%5B%7B%22name%22%3A%22messagesHub%22%7D%5D"',
          response: `{
  "Url": "/signalr",
  "ConnectionToken": "rFyaKBwKseZme6iuhdycXa04MywzQO92AjRePDZ05VKLfVpd5oYJscb0yilk5ERPmEREg+c6/sWveYRsyLKSo+t5Id5ZhrzX8nxp6yuCJcZLvAuPC4XN8+qPOUwML41g",
  "ConnectionId": "a2340e94-2f8d-4b59-b2d7-06d84535b23f",
  "KeepAliveTimeout": 20.0,
  "DisconnectTimeout": 30.0,
  "ConnectionTimeout": 110.0,
  "TryWebSockets": true,
  "ProtocolVersion": "1.2",
  "TransportConnectTimeout": 5.0
}`,
          findings: [
            "SignalR negotiation is accessible without authentication",
            "A valid ConnectionToken was issued",
            "No authentication credentials were required",
            "Transport methods available: WebSockets, Server-Sent Events (SSE), Long Polling"
          ]
        },
        {
          title: "Testing Server Availability",
          description: "Confirm that the SignalR service is active and listening for connections.",
          command: 'curl -v "https://staging-customerportal.more.com.au/signalr/"',
          response: "HTTP/1.1 200 OK",
          findings: [
            "The server is live and responding to requests",
            "The SignalR service is reachable from external sources"
          ]
        }
      ],
      key_issues: [
        "Unauthenticated users can obtain SignalR connection tokens",
        "Polling works without authentication, meaning messages may be leaked",
        "Tokens are passed in URLs, making them vulnerable to exposure in logs, referrer headers, and browser history",
        "Message sending behavior is uncertain, requiring further investigation",
        "No apparent token expiration, making session hijacking a risk"
      ],
      summary: [
        "Successfully connected to the SignalR hub without authentication",
        "Confirmed token validity when used with correct transport parameters",
        "Confirmed ability to passively receive messages (possible information leakage)",
        "Sending messages may require additional parameters, but further testing is needed"
      ]
    }
  }
  // ... other findings ...
];

/**
 * Generate and download a Word document version of the VAPT report
 */
export async function generateWordReport(reportData: ReportData): Promise<void> {
  try {
    const response = await fetch(`${API_URL}/generate-report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(reportData)
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    // Get the filename from the Content-Disposition header
    const contentDisposition = response.headers.get('Content-Disposition');
    const filenameMatch = contentDisposition?.match(/filename="?([^"]+)"?/);
    const filename = filenameMatch ? filenameMatch[1] : 'VAPT_Report.docx';

    // Create a blob from the response
    const blob = await response.blob();
    
    // Create a download link and trigger it
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    // Cleanup
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (error) {
    console.error('Error generating Word report:', error);
    throw error;
  }
}