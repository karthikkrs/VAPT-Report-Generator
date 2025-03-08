# VAPT Report Generator

A comprehensive tool for generating Vulnerability Assessment and Penetration Testing (VAPT) reports with a FastAPI backend and React frontend.

## Features

- Generate detailed VAPT reports with findings, replication steps, and recommendations
- Support for MITRE ATT&CK framework mapping
- Developer recommendations for remediation
- Customizable report templates
- Interactive UI for managing findings and report generation

## Project Structure

- `backend/`: FastAPI server and report generation logic
- `vapt-report/`: React frontend for the application

## Setup Instructions

### Backend

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the server:
   ```bash
   python server.py
   ```

### Frontend

1. Navigate to the frontend directory:
   ```bash
   cd vapt-report
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

## Usage

1. Access the frontend at http://localhost:3000
2. Create findings with detailed information
3. Generate reports through the UI
4. Download and share the generated reports

## Requirements

- Python 3.8+
- Node.js 14+
- Graphviz (for attack flow diagrams)

## License

MIT