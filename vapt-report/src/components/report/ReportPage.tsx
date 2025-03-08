import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Layout } from '@/components/layout/Layout';
import { ReportSummary } from '@/components/report/ReportSummary';
import { FindingsList } from '@/components/report/FindingsList';
import { MethodologyConclusion } from '@/components/report/MethodologyConclusion';
import { ReportData } from '@/lib/api';

// Hardcoded VAPT report data
const hardcodedReportData: ReportData = {
  metadata: {
    title: "Vulnerability Assessment and Penetration Testing (VAPT)",
    author: "vCyberiz SCS",
    subject: "External WebApp Technical Report",
    keywords: "VAPT, security, vulnerability, penetration testing, black box testing",
    creator: "vCyberiz SCS",
    producer: "vCyberiz SCS",
    page_count: 24,
    file_size: 4104520,
    assessment_date: "February 27, 2025 - March 2, 2025",
    test_type: "Black Box"
  },
  content: {
    title: "More Web Application VAPT Report",
    executive_summary: "Our comprehensive Vulnerability Assessment and Penetration Testing (VAPT) of the More Web Application has revealed a robust security foundation. The assessment identified a total of 3 findings: 1 medium-severity and 2 low-severity issues, indicating an overall positive security posture. The application demonstrates strong security controls and best practices in most areas, with only minor enhancements recommended to further strengthen its security stance.",
    findings: [
      {
        title: "Unauthenticated Access to Hub (SignalR)",
        severity: "Medium",
        description: "SignalR can be used with ASP.NET Core authentication to associate a user with each connection. In a hub, authentication data can be accessed from the HubConnectionContext.User property. Authentication allows the hub to call methods on all connections associated with a user. For more information, see Manage users and groups in SignalR. Multiple connections may be associated with a single user.",
        impact: "• Moderate risk due to data exposure in a customer-facing system.\n• Potential compliance issues if sensitive information is leaked.\n• Reputation damage if customers receive spoofed messages.",
        remediation: "• Implement authentication on SignalR hubs.\n• Secure token handling (short expiration, move to headers).\n• Restrict transport methods to WebSockets.\n• Disable detailed error messages.\n• Sanitize input to prevent XSS.",
        affected_url: "https://staging-customerportal.more.com.au/signalr",
        reference: "https://learn.microsoft.com/en-us/aspnet/core/signalr/authn-and-authz?view=aspnetcore-9.0"
      },
      {
        title: "Outdated jQuery Version",
        severity: "Low",
        description: "The web application is using jQuery version 2.2.4, which was released in 2016. This version has known security vulnerabilities and is no longer maintained.",
        impact: "• Low risk due to outdated jQuery library in customer-facing system\n• Limited compliance impact as no sensitive data is directly affected\n• Minimal reputation impact as vulnerabilities require specific exploitation conditions",
        remediation: "• Update jQuery to the latest stable version (3.7.1 or newer)\n• Implement regular dependency updates\n• Add security headers including CSP\n• Test thoroughly after update",
        affected_url: "https://staging-customerportal.more.com.au/lib/jquery/jquery.min.js",
        reference: "https://jquery.com/upgrade-guide/3.0/"
      },
      {
        title: "Web Server Information Disclosure",
        severity: "Low",
        description: "The web server is disclosing version information through HTTP headers, which could aid attackers in identifying potential vulnerabilities specific to the version being used.",
        impact: "• Low risk due to information disclosure in HTTP headers\n• Limited compliance impact as no sensitive data is directly exposed\n• Minimal reputation impact as this is a common configuration issue",
        remediation: "• Configure web server to remove or modify server headers\n• Implement security headers\n• Use URL rewrite rules to remove server information\n• Regular security audits",
        affected_url: "https://staging-customerportal.more.com.au",
        reference: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
      }
    ],
    methodology: "The VAPT assessment followed industry-standard methodologies including OWASP Testing Guide v4.2 and NIST guidelines. Both automated and manual testing techniques were employed.",
    recommendations: [
      "Update all outdated dependencies to their latest stable versions",
      "Implement proper authentication for all endpoints",
      "Configure security headers appropriately",
      "Regular security assessments and updates"
    ],
    conclusion: "Our comprehensive security assessment has revealed that the More Web Application demonstrates a strong foundation in security practices, with only a few areas requiring enhancement. The assessment identified a total of 3 findings, comprising 1 medium-severity and 2 low-severity issues, which is notably positive for a modern web application.\n\nFindings Summary:\n• Medium Severity (1):\n  - Unauthenticated Access to SignalR Hub - A configuration issue that can be readily addressed\n• Low Severity (2):\n  - Outdated jQuery Version - Standard maintenance update required\n  - Web Server Information Disclosure - Minor configuration adjustment needed\n\nDemonstrated Security Strengths:\n• Robust Authentication Framework: The application implements strong authentication mechanisms across most endpoints\n• Secure Data Handling: Proper encryption and data protection measures are in place\n• Input Validation: Comprehensive input validation and sanitization across user interfaces\n• Security Headers: Implementation of essential security headers in most areas\n• Error Handling: Secure error handling preventing information disclosure\n• Access Controls: Well-structured role-based access control system\n• Regular Updates: Evidence of consistent security patch management\n\nGood Development Practices Observed:\n• Use of Modern Frameworks: Implementation of current development frameworks\n• Code Quality: Well-structured and maintainable codebase\n• Security by Design: Security considerations evident in architecture\n• Documentation: Comprehensive API and security documentation\n• Monitoring: Logging and monitoring systems in place\n\nRecommended Enhancements:\n• Implement authentication for SignalR hub connections\n• Update jQuery to the latest stable version\n• Configure web server headers to minimize information disclosure\n• Continue regular security assessments and updates\n\nConclusion:\nThe application exhibits a mature security posture with well-implemented controls and security-conscious development practices. The identified issues are common in web applications and can be addressed through routine maintenance. The development team's commitment to security is evident in the overall architecture and implementation. Addressing the recommended enhancements will further strengthen the application's already robust security foundation."
  }
};

export function ReportPage() {
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate loading to show the transition
    const timer = setTimeout(() => {
      setReportData(hardcodedReportData);
      setLoading(false);
    }, 1000);
    
    return () => clearTimeout(timer);
  }, []);

  return (
    <Layout>
      {loading ? (
        <div className="flex justify-center items-center min-h-[60vh]">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
        </div>
      ) : reportData ? (
        <motion.div 
          className="space-y-6"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          <ReportSummary 
            metadata={reportData.metadata} 
            content={reportData.content} 
          />
          
          <FindingsList findings={reportData.content.findings} />
          
          <MethodologyConclusion 
            methodology={reportData.content.methodology} 
            conclusion={reportData.content.conclusion} 
          />
        </motion.div>
      ) : (
        <div className="text-center py-10">
          <p className="text-muted-foreground">No report data available.</p>
        </div>
      )}
    </Layout>
  );
}