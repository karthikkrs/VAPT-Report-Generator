import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pdf_processor import process_pdf
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import List, Optional
from report_generator import generate_report

app = FastAPI(title="VAPT Report API", description="API for processing VAPT PDF reports")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Path to the PDF file
PDF_PATH = "More Web Application VAPT Report.pdf"

class Finding(BaseModel):
    title: str
    severity: str
    description: str
    impact: str
    remediation: str
    affected_url: str
    reference: str

class ReportContent(BaseModel):
    title: str
    executive_summary: str
    findings: List[Finding]
    methodology: Optional[str] = None
    recommendations: Optional[List[str]] = None
    conclusion: Optional[str] = None

class Metadata(BaseModel):
    title: str
    author: str
    subject: str
    keywords: Optional[str] = None
    creator: Optional[str] = None
    producer: Optional[str] = None
    page_count: Optional[int] = None
    file_size: Optional[int] = None
    assessment_date: str
    test_type: str

class ReportData(BaseModel):
    metadata: Metadata
    content: ReportContent

@app.get("/")
async def root():
    return {"message": "VAPT Report API is running"}

@app.get("/api/report")
async def get_report():
    """Get the processed VAPT report data."""
    if not os.path.exists(PDF_PATH):
        raise HTTPException(status_code=404, detail="PDF file not found")
    
    try:
        report_data = process_pdf(PDF_PATH)
        return JSONResponse(content=report_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing PDF: {str(e)}")

@app.get("/api/report/metadata")
async def get_metadata():
    """Get only the metadata of the VAPT report."""
    if not os.path.exists(PDF_PATH):
        raise HTTPException(status_code=404, detail="PDF file not found")
    
    try:
        report_data = process_pdf(PDF_PATH)
        return JSONResponse(content={"metadata": report_data.get("metadata", {})})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing PDF: {str(e)}")

@app.get("/api/report/content")
async def get_content():
    """Get only the content of the VAPT report."""
    if not os.path.exists(PDF_PATH):
        raise HTTPException(status_code=404, detail="PDF file not found")
    
    try:
        report_data = process_pdf(PDF_PATH)
        return JSONResponse(content={"content": report_data.get("content", {})})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing PDF: {str(e)}")

@app.post("/api/generate-report")
async def generate_vapt_report(report_data: ReportData):
    try:
        # Generate the report
        report_file = generate_report(report_data.dict())
        
        # Return the file
        return FileResponse(
            report_file,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=os.path.basename(report_file)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)