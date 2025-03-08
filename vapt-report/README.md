# VAPT Report Frontend

This is the frontend application for the VAPT Report Generator, built with React, TypeScript, and Tailwind CSS.

## Project Structure

- `src/` - Source code directory
  - `components/` - React components
    - `layout/` - Layout components (header, footer, etc.)
    - `report/` - Report-specific components
    - `ui/` - Reusable UI components
  - `lib/` - Utility functions and API services
  - `assets/` - Static assets (images, icons, etc.)
  - `App.tsx` - Main application component
  - `main.tsx` - Application entry point

## Key Components

- `ReportPage.tsx` - Main page component that displays the VAPT report
- `FindingsList.tsx` - Component for displaying the list of findings
- `ReportSummary.tsx` - Component for displaying the report summary
- `MethodologyConclusion.tsx` - Component for displaying methodology and conclusion

## API Integration

The frontend communicates with the FastAPI backend to:
- Fetch report data
- Generate Word document reports

## Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

3. Build for production:
   ```bash
   npm run build
   ```

## Technologies Used

- React 19
- TypeScript
- Tailwind CSS
- Framer Motion (for animations)
- Radix UI (for accessible components)
- Vite (for build tooling)